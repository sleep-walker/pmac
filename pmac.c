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

#define pmac_version	"0.1"

#define addr_len	6
#define vendor_len	3
#define extra_bytes	1
#define random_device	"/dev/urandom"



struct vendor_mac {
	char *name;
	char mac[3];
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
		printf("Cannot read %d bytes from %s. Read only %ld bytes.\n", addr_len, random_device, num);
	fclose(random_file);
	return num = addr_len;
}

void print_address(unsigned char *addr) {
	int i;

	for (i = 0; i < addr_len - 1; ++i)
		printf("%2.02x:", (unsigned char)addr[i]);
	printf("%2.02x\n", (unsigned char)addr[addr_len - 1]);
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
	unsigned char *hwaddr;

	strncpy(ifr.ifr_name, interface, strlen(interface) + 1);
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		return 0;
	}
	hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	printf("present MAC address: ");
	print_address(hwaddr);
	addr[0] = hwaddr[0];
	addr[1] = hwaddr[1];
	addr[2] = hwaddr[2];
	return 1;
}

int set_address_to_interface(char *interface, unsigned char *addr) {
	struct ifreq ifr;

	strncpy(ifr.ifr_name, interface, strlen(interface) + 1);
	memcpy(&(ifr.ifr_hwaddr.sa_data), addr, sizeof(struct sockaddr));
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	printf("Setting address to interface\n");
	if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCSIFHWADDR)");
		return 0;
	}
	return 1;
}

int select_vendor(unsigned char *addr, char *vendor) {
	int i;
	int len = strlen(vendor);
	int num = sizeof(vendors) / sizeof(struct vendor_mac);
       
	if (len == 0) {
		printf("Vendor name is empty.\n");
		return 0;
	}

	if (!strncmp("same", vendor, len)) {
		unsigned char old_addr[addr_len];
		if (!get_address_from_interface(interface, old_addr))
			return 0;
		addr[0] = old_addr[0];
		addr[1] = old_addr[1];
		addr[2] = old_addr[2];
		return 1;

	}
	if (!strncmp("random", vendor, len)) {
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
	addr[0] = vendors[i].mac[0];
	addr[1] = vendors[i].mac[1];
	addr[2] = vendors[i].mac[2];
	return 1;
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
		{"help",      0, 0, 'h'},
		{0, 0, 0, 0},
	};

	/* command line parsing */
	while (1) {
		int idx;

		c = getopt_long(argc, argv, "hpv:i:m:", longopts, &idx);
		if (c == -1)
			break;

		switch(c) {
			case 'v':
				if(optarg) {
					vendor = malloc(sizeof(optarg) + 1);
					printf("vendor: %s\n", optarg);
					strncpy(vendor, optarg, sizeof(optarg) + 1);
				}
				break;
			case 'i':
				if(optarg) {
					interface = malloc(sizeof(optarg) + 1);
					printf("interface: %s\n", optarg);
					strncpy(interface, optarg, sizeof(optarg) + 1);
				}
				break;
			case 'p':
				print = 1;
				break;
			case 'h':
				print_help();
				return 0;
				break;
			case 'm':
				if(optarg) {
					manually = malloc(sizeof(optarg) + 1);
					printf("manually: %s\n", optarg);
					strncpy(manually, optarg, sizeof(optarg) + 1);
				}
				break;
			case '?':
				cleanup();
				return 1;
				break;
		}

	}

	if (!read_random_buf()) {
		cleanup();
		return 1;
	}
	init_socket();
	if (!vendor) {
		printf("Vendor not set, using 'random' as default\n");
		vendor = malloc(sizeof("random"));
		strncpy(vendor, "random", sizeof("random"));
	}
	if (!select_vendor(addr, vendor)) {
		cleanup();
		return 1;
	}
	generate_device_part(addr);
	if (interface)
		if (print)
			print_address(addr);
		else {
			if (!set_address_to_interface(interface, addr)) {
				cleanup();
				return 1;
			}
		}
	else {
		if (!print)
			printf("Interface not set, printing...\n");
		print_address(addr);
	}
	cleanup();
	return EXIT_SUCCESS;
}
