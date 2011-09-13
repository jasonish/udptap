/*
 * Copyright (c) 2003 Jason Ish <jason@codemonkey.net>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Linux stuff. */
#ifdef __linux__
#define __FAVOR_BSD 1
#define __USE_BSD 1
#include <features.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>

#include <pcap.h>

#define DLT_LINUX_SLL_OFF    16
#define DLT_EN10MB_OFF       16

#define DEFAULT_PCAP_SNAPLEN 0xffff

static struct sockaddr_in dest_addr;
static int sockfd;
static int linktype;
static int ip_offset;

static void
udp_resend(const u_char *buf, size_t len)
{
	ssize_t wlen = sendto(sockfd, buf, len, 0, (struct sockaddr *)&dest_addr,
            sizeof(dest_addr));
	if (wlen == -1) {
		warn("sendto failed");
	}
	else if (wlen != len) {
		warnx("send %zd bytes, expected to send %zd", wlen, len);
	}
}

static void
make_socket(char *host, char *portstring)
{
	char *endptr;
	long int port;

	port = strtol(portstring, &endptr, 10);
	if ((errno == ERANGE || (errno != 0 && port == 0)) ||
	    (endptr == optarg)) {
		errx(1, "Invalid destination port: %s", portstring);
	}
	if (port < 1 || port > 0xffff) {
		errx(1, "Invalid destination port: %s", portstring);
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(port);
	if (inet_aton(host, &dest_addr.sin_addr) == 0) {
		errx(1, "Invalid destination IP: %s", host);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 1) {
		err(1, "Failed to create socket");
	}
}

static void
pcap_cb(u_char *u, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	struct ip *ip = (struct ip *)(pkt + ip_offset);
	int hlen = ip->ip_hl << 2;
	int data_offset = ip_offset + hlen + sizeof(struct udphdr);
	udp_resend(pkt + data_offset, hdr->caplen - data_offset);
}

static void
print_usage(FILE *out)
{
        static char usage[] = "\n" \
            "usage: udptap [options]\n\n"
            "Options:\t\n"
            "\t-i <interface>      Interface to tap\n"
            "\t-u <port>           UDP port to tap\n"
            "\t-d <host>           Destination host\n"
            "\t-p <port>           Destination port\n"
            "\n"
            ;
        fprintf(out, "%s", usage);
}

int
main(int argc, char **argv)
{
	char ch;
	char *interface = NULL;
	pcap_t *pcap;
	struct bpf_program bpf;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	char filter[128];
	char *dest_host = NULL;
	char *dest_port = NULL;
        char *tap_port = NULL;

	while ((ch = getopt(argc, argv, "hi:d:p:u:")) != -1) {
		switch (ch) {
                case 'h':
                        print_usage(stdout);
                        exit(0);
		case 'p':
			dest_port = optarg;
			break;
		case 'd':
			dest_host = optarg;
			break;
		case 'i':
			interface = optarg;
			break;
                case 'u':
                        tap_port = optarg;
                        break;
		default:
			print_usage(stderr);
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (dest_host == NULL || dest_port == NULL) {
		errx(1, "Invalid usage: -d and -p are both required.");
	}
	make_socket(dest_host, dest_port);

	/* Open device. */
	if (interface == NULL) {
		printf("No interface supplied, looking up.\n");
		interface = pcap_lookupdev(pcap_errbuf);
		if (interface == NULL) {
			errx(1, "Failed to lookup interface: %s",
			     pcap_errbuf);
		}
		printf("Found interface: %s\n", interface);
	}

	pcap = pcap_open_live(interface, DEFAULT_PCAP_SNAPLEN,
			      1, 0, pcap_errbuf);
	if (pcap == NULL) {
		errx(1, "Failed to open %s: %s", interface,
		     pcap_errbuf);
	}
        linktype = pcap_datalink(pcap);
        switch (linktype) {
        case DLT_EN10MB:
            ip_offset = DLT_EN10MB_OFF;
            break;
        case DLT_LINUX_SLL:
            ip_offset = DLT_LINUX_SLL_OFF;
            break;
        case DLT_RAW:
            ip_offset = 0;
            break;
        default:
            errx(1, "Unsupported link type on %s: %s", interface,
                pcap_datalink_val_to_name(linktype));
        }
	printf("Interface %s (%s) opened.\n", interface, 
            pcap_datalink_val_to_name(linktype));


        snprintf(filter, sizeof(filter), "udp and port %s", tap_port);
        if (pcap_compile(pcap, &bpf, filter, 1, 0) == -1) {
                errx(1, "Failed to compile filter: %s", 
                    pcap_geterr(pcap));
        }
        if (pcap_setfilter(pcap, &bpf) == -1) {
                errx(1, "Failed to set filter: %s", pcap_geterr(pcap));
        }

	printf("Listening.\n");
	pcap_loop(pcap, -1, pcap_cb, NULL);

	return 0;
}
