#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>

/* 1) choose MAC address type
 * 2) generate random
 * 3) set to specified interface
 *
 * 1) MAC address type
 *    - locally administered (default off)
 *    - same vendor in auto mode (interface specified)
 *    - specified vendor
 *    - random known vendor
 *    - randomize vendor part
 *  2) generate random
 *  3) print or set to specified interface
 */

#define pmac_version		"0.1"

/* source of numbers */
#define random_device		"/dev/urandom"

/* length of HW address */
#define addr_len		6

/* length of vendor specific part of HW address */
#define vendor_len		3

/* number of random bytes read too - used internally */
#define extra_bytes		1

/* default choice */
#define default_choice		"any"

struct vendor_mac {
	char *name;
	unsigned char mac[3];
};

/* configuration read from command line */
int print;
char *vendor, *interface, *manually;

/* buffer for storing random values */
unsigned char buf[addr_len + extra_bytes];

/* AF_INET socket for ioctl() calls.*/
int skfd = -1;


struct vendor_mac vendors[] = {
	{ "intel", "\x05\x04\x03" },
};

int read_random_buf(void) {
	FILE *random_file = fopen(random_device, "r");
	size_t num;

	if (!random_file)
		return 1;

	num = fread(buf, sizeof(char), addr_len, random_file);
	if (num < addr_len)
		printf("Cannot read %d bytes from %s. Read only %d bytes.\n", addr_len, random_device, num);
	fclose(random_file);
	return num = addr_len;
}

void generate_device_part(unsigned char *addr) {
	int i;

	for (i = vendor_len; i < addr_len; ++i)
		addr[i] = buf[i];
}

int init_socket(void) {
	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return 1;
	}
	return 0;
}

int get_address_from_interface(char *interface, unsigned char *addr) {
	struct ifreq ifr;

	strncpy(ifr.ifr_name, interface, strlen(interface));
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Cannot read HW address from interface:\n");
		perror("ioctl(SIOCGIFHWADDR)");
		return 0;
	}
	memcpy(addr, ifr.ifr_hwaddr.sa_data, vendor_len);
	return 1;
}

int set_address_to_interface(char *interface, unsigned char *addr) {
	struct ifreq ifr;

	strncpy(ifr.ifr_name, interface, strlen(interface));
	memcpy(&(ifr.ifr_hwaddr), addr, sizeof(struct sockaddr));
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	printf("Setting address to interface\n");
	if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
		printf("Cannot assign HW address to interface:\n");
		perror("ioctl(SIOCSIFHWADDR)");
		return 0;
	}
	return 1;
}

void list_vendors(void) {
	int i,j;

	for (i = 0; i < sizeof(vendors) / sizeof(struct vendor_mac); ++i) {
		printf("%-20s", vendors[i].name);
		for (j = 0; j < vendor_len; ++j)
			printf("%2.02x:", vendors[i].mac[j]);
		printf("...\n");
	}
	printf(
		"%-20sselect any vendor mentioned above\n"
		"%-20suse the same vendor as interface specified with -i\n"
		"%-20sgenerate random vendor\n",
		"any", "same", "random");
}

int select_vendor(unsigned char *addr, char *vendor) {
	int i;
	int len = strlen(vendor);
	int num = sizeof(vendors) / sizeof(struct vendor_mac);
       
	if (len == 0) {
		printf("Vendor name is empty.\n");
		return 0;
	}

	if (!strncmp("same", vendor, len))
		return get_address_from_interface(interface, addr);

	if (!strncmp("random", vendor, len)) {
		memcpy(buf, addr, vendor_len);
		return 1;

	}
	if (!strncmp("any", vendor, len)) {
		i = buf[addr_len + 1] % num;
	}
	else {
		/* find it */
		for (i = 0; i < num; ++i)
			if (strcmp(vendors[i].name, vendor) == 0)
				break;
		if (i == num) {
			printf("Vendor '%s' not found.\n", vendor);
			return 0;
		}
	}
	memcpy(addr, vendors[i].mac, vendor_len);
	return 1;
}

inline int hexa_digit(char digit) {

	if ((digit >= '0') && (digit <= '9'))
		return digit - '0';
	if ((digit >= 'a') && (digit <= 'f'))
		return digit - 'a' + 10;
	if ((digit >= 'A') && (digit <= 'F'))
		return digit - 'A' + 10;
	return -1;
}

int parse_manual_address(char *input, unsigned char *addr) {
	char *ptr;
	char separator = 0;
	enum state_type {
		first,
		second,
		separ
	} state = first;
	int tmp;

	if ((strlen(input) != addr_len * 2) && (strlen(input) != addr_len * 3 - 1)) {
		printf("Unexpected length of manually set address.\n");
		return 0;
	}

	if ((hexa_digit(input[2]) == -1) || (strlen(input) == addr_len * 3 - 1)) 
		/* there is separator or input is invalid */
		separator = input[2];

	for (ptr = input; ptr - input < strlen(input); ++ptr) {
		tmp = hexa_digit(*ptr);
		switch(state) {
			case first:
				/* we're reading first digit */
				if (tmp >= 0)
					addr[separator ? (ptr - input)/3 : (ptr - input)/2] = tmp << 4;
				else {
					printf("Unexpected character '%c' in the positition %d of MAC address (expected first digit\n", *ptr, ptr - input + 1);
					return 0;
				}
				state = second;
				break;
			case second:
				/* we're reading second digit */
				if (tmp >= 0)
					addr[separator ? (ptr - input)/3 : (ptr - input)/2] |= tmp;
				else {
					printf("Unexpected character '%c' in the positition %d of MAC address (expected second digit)\n", *ptr, ptr - input + 1);
					return 0;
				}
				if (separator)
					state = separ;
				else
					state = first;

				break;
			case separ:
				/* we're reading separator */
				if (*ptr != separator) {
					printf("Unexpected separator '%c' in the position %d of MAC address\n", *ptr, ptr - input + 1);
					return 0;
				}
				state = first;
				break;
		}

	}
	return 1;
}

void print_address(unsigned char *addr) {
	int i;

	for (i = 0; i < addr_len - 1; ++i)
		printf("%02x:", addr[i]);
	printf("%02x\n", addr[addr_len - 1]);
}

void cleanup(void) {
	if (vendor)
		free(vendor);
	if (interface)
		free(interface);
	if (manually)
		free(manually);
	if (skfd != -1)
		close(skfd);
}

void print_help(void) {
	printf(
		"pmac v%s - proper MAC generator\n"
		"generate random MAC address and set to interface\n"
		"\n"
		"Usage:\n"
		"\tpmac [ -p | --print ] [ -i | --interface int ] [ -v | --vendor name ]\n"
	       	"\t     [ -m | --manually addr ] [ -h | --help ]\n"
		"\n"
		"-p  --print          instead of setting MAC address just print it\n"
		"-i  --interface int  interface to read MAC address and/or to write MAC to\n"
		"-v  --vendor name    vendor name to be used for vendor part of MAC address\n"
		"-m  --manually addr  do not generate random, manually set address to addr\n"
		"-l  --list           list supported vendor names\n"
		"-h  --help           print this screen\n"
		"\n", pmac_version);
}

int main(int argc, char *argv[]) {
	unsigned char addr[] = { 0, 1, 2, 3, 4, 5 };
	int c;
	struct option longopts[] = {
		{"vendor",    1, 0, 'v'},
		{"interface", 1, 0, 'i'},
		{"print",     0, 0, 'p'},
		{"manually",  1, 0, 'm'},
		{"vendor",    0, 0, 'l'},
		{"help",      0, 0, 'h'},
		{0, 0, 0, 0},
	};

	/* command line parsing */
	while (1) {
		int idx;

		c = getopt_long(argc, argv, "lhpv:i:m:", longopts, &idx);
		if (c == -1)
			break;

		switch(c) {
			case 'v':
				if(optarg) {
					printf("vendor: %s\n", optarg);
					vendor = malloc(strlen(optarg) + 1);
					strncpy(vendor, optarg, strlen(optarg) + 1);
				}
				break;
			case 'i':
				if(optarg) {
					printf("interface: %s\n", optarg);
					interface = malloc(strlen(optarg) + 1);
					strncpy(interface, optarg, strlen(optarg) + 1);
				}
				break;
			case 'p':
				print = 1;
				break;
			case 'l':
				list_vendors();
				cleanup();
				return 0;
				break;
			case 'h':
				print_help();
				cleanup();
				return 0;
				break;
			case 'm':
				if(optarg) {
					manually = malloc(strlen(optarg) + 1);
					printf("manually: %s\n", optarg);
					strncpy(manually, optarg, strlen(optarg) + 1);
				}
				break;
			case '?':
				cleanup();
				return 1;
				break;
		}

	}

	/* read all needed random numbers in one step */
	if (!read_random_buf()) {
		cleanup();
		return 1;
	}

	/* open socket for getting/setting HW address from/to interface */
	init_socket();

	if (!manually) {
		/* if address is not set manually, check for specified vendor */
		if (!vendor) {
			/* if vendor is not specified, use default */
			printf("Vendor not set, using '%s' as default\n", default_choice);
			vendor = malloc(strlen(default_choice + 1));
			strncpy(vendor, default_choice, strlen(default_choice) + 1);
		}

		/* prepare vendor part of address */
		if (!select_vendor(addr, vendor)) {
			cleanup();
			return 1;
		}

		/* prepare device part of address */
		generate_device_part(addr);
	}
	else {
		/* address set manually - read it */
		if (!parse_manual_address(manually, addr))
			return 1;
	}

	if (interface)
		/* interface defined */
		if (print)
			/* but address should be printed */
			print_address(addr);
		else {
			/* set address to interface */
			if (!set_address_to_interface(interface, addr)) {
				cleanup();
				return 1;
			}
		}
	else {
		/* interface not set - I can only print result */
		if (!print)
			printf("Interface not set, printing...\n");
		print_address(addr);
	}

	/* free all buffers and socket */
	cleanup();
	return EXIT_SUCCESS;
}
