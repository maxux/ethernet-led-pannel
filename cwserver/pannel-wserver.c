#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libwebsockets.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <jansson.h>

#define MAX_PAYLOAD_SIZE 1024
#define ARDUINO_BUFFER   1024

struct color_session {
    unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
    unsigned int len;
};

typedef struct color_t {
    uint8_t red;
    uint8_t green;
    uint8_t blue;

} color_t;

const uint8_t dstaddr[] = {
    0xA2, 0x43, 0x42, 0x42, 0x42, 0x01
};

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

static int arduino_frame(char *interface, color_t *color) {
    int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
    char sendbuf[ARDUINO_BUFFER];
    struct ether_header *eh = (struct ether_header *) sendbuf;
    struct sockaddr_ll saddr;
    int length = 0;

	if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	    diep("socket");

    memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);

    if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interface, IFNAMSIZ - 1);

	if(ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

    memset(sendbuf, 0, ARDUINO_BUFFER);

    memcpy(eh->ether_shost, if_mac.ifr_hwaddr.sa_data, 6);
    memcpy(eh->ether_dhost, dstaddr, 6);

	eh->ether_type = 0xb688;
	length += sizeof(struct ether_header);

    sendbuf[length + 0] = color->red;
	sendbuf[length + 1] = color->green;
	sendbuf[length + 2] = color->blue;

    length += 3;

    saddr.sll_ifindex = if_idx.ifr_ifindex;
	saddr.sll_halen = ETH_ALEN;
	memcpy(saddr.sll_addr, dstaddr, 6);

    if(sendto(sockfd, sendbuf, length, 0, (struct sockaddr *) &saddr, sizeof(struct sockaddr_ll)) < 0)
        perror("send");

    return 0;
}

color_t *color_json(void *buffer, size_t length, color_t *color) {
    json_t *root;
    json_error_t error;
    json_t *object;

    if(!(root = json_loadb(buffer, length, 0, &error))) {
        fprintf(stderr, "json error: on line %d: %s\n", error.line, error.text);
        return NULL;
    }

    object = json_object_get(root, "r");
    if(json_is_integer(object))
        color->red = json_integer_value(object);

    object = json_object_get(root, "g");
    if(json_is_integer(object))
        color->green = json_integer_value(object);

    object = json_object_get(root, "b");
    if(json_is_integer(object))
        color->blue = json_integer_value(object);

    json_decref(root);

    return color;
}

static int callback_color(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct color_session *pss = (struct color_session *) user;
    color_t color;
    int n;

    if(reason == LWS_CALLBACK_ESTABLISHED) {
        printf("[+] new connection\n");
        pss->len = -1;
        return 0;
    }

    if(reason == LWS_CALLBACK_SERVER_WRITEABLE) {
        if ((int) pss->len == -1)
            return 0;

        n = LWS_WRITE_TEXT;
        n = lws_write(wsi, &pss->buf[LWS_PRE], pss->len, n);

        if(n < 0) {
            lwsl_err("ERROR %d writing to socket, hanging up\n", n);
            return 1;
        }

        if(n < (int) pss->len) {
            lwsl_err("Partial write\n");
            return -1;
        }

        pss->len = -1;

        lws_rx_flow_control(wsi, 1);
        return 0;
    }

    if(reason == LWS_CALLBACK_RECEIVE) {
        memcpy(&pss->buf[LWS_PRE], in, len);
        pss->len = (unsigned int) len;

        if(lws_is_final_fragment(wsi)) {
            printf(">> <%.*s>\n", pss->len, pss->buf + LWS_PRE);

            if(color_json(pss->buf + LWS_PRE, pss->len, &color))
                arduino_frame("bond0", &color);
        }

        lws_rx_flow_control(wsi, 0);
        lws_callback_on_writable(wsi);

        return 0;
    }

    return 0;
}

static struct lws_protocols protocols[] = {
    {"", callback_color, sizeof(struct color_session), MAX_PAYLOAD_SIZE, 0, NULL, 0},
    {NULL, NULL, 0, 0, 0, NULL, 0}
};

static const struct lws_extension exts[] = {
    {NULL, NULL, NULL}
};

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;

    int port = 7681;
    struct lws_context *context;
    int listen_port = port;
    struct lws_context_creation_info info;

    memset(&info, 0, sizeof(info));
    printf("[+] initializing\n");

    info.port = listen_port;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.extensions = exts;

    if((context = lws_create_context(&info)) == NULL) {
        lwsl_err("libwebsocket init failed\n");
        exit(EXIT_FAILURE);
    }

    int n = 1;

    while(n >= 0)
        n = lws_service(context, 10);

    lws_context_destroy(context);

    return 0;
}
