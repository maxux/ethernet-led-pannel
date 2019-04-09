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
#include <signal.h>

#define DEFAULT_INTERFACE  "eth0"
#define MAX_PAYLOAD_SIZE   1024
#define ARDUINO_BUFFER     1024

struct color_session {
    unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
    unsigned int len;
};

typedef struct color_t {
    uint8_t red;
    uint8_t green;
    uint8_t blue;

} color_t;

typedef struct pannel_t {
    int sockfd;
    uint8_t srcaddr[ETHER_ADDR_LEN];
    uint8_t dstaddr[ETHER_ADDR_LEN];
    int ifindex;
    color_t color;

} pannel_t;

const uint8_t dstaddr[] = {
    0xA2, 0x43, 0x42, 0x42, 0x42, 0x01
};

int stop_requested = 0;



void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

static pannel_t *socket_connect(pannel_t *pannel, char *interface, const uint8_t *destination) {
	struct ifreq ifdata;

    // create raw socket
	if((pannel->sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0)
	    diep("socket");

    // get interface index
    memset(&ifdata, 0, sizeof(struct ifreq));
	strncpy(ifdata.ifr_name, interface, IFNAMSIZ - 1);
    if(ioctl(pannel->sockfd, SIOCGIFINDEX, &ifdata) < 0)
	    diep("SIOCGIFINDEX");

    pannel->ifindex = ifdata.ifr_ifindex;

    // get interface mac address
	if(ioctl(pannel->sockfd, SIOCGIFHWADDR, &ifdata) < 0)
	    diep("SIOCGIFHWADDR");

    // set pannel source and destination mac addresses
    memcpy(pannel->srcaddr, ifdata.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    memcpy(pannel->dstaddr, destination, ETHER_ADDR_LEN);

    return pannel;
}

static int arduino_frame(pannel_t *pannel) {
    char sendbuf[ARDUINO_BUFFER];
    struct ether_header *eh = (struct ether_header *) sendbuf;
    struct sockaddr_ll saddr;
    int length = 0;

    memset(sendbuf, 0, ARDUINO_BUFFER);

    // set source and destination frame
    memcpy(eh->ether_shost, pannel->srcaddr, ETHER_ADDR_LEN);
    memcpy(eh->ether_dhost, pannel->dstaddr, ETHER_ADDR_LEN);

    // set frame type
	eh->ether_type = 0xb688;
	length += sizeof(struct ether_header);

    // set frame payload
    sendbuf[length + 0] = pannel->color.red;
	sendbuf[length + 1] = pannel->color.green;
	sendbuf[length + 2] = pannel->color.blue;
    length += 3;

    // set socket frame metadata
    saddr.sll_ifindex = pannel->ifindex;
	saddr.sll_halen = ETH_ALEN;
	memcpy(saddr.sll_addr, pannel->dstaddr, ETHER_ADDR_LEN);

    if(sendto(pannel->sockfd, sendbuf, length, 0, (struct sockaddr *) &saddr, sizeof(struct sockaddr_ll)) < 0)
        perror("send");

    return 0;
}

color_t *color_json(void *buffer, size_t length, color_t *color) {
    json_t *root;
    json_error_t error;
    json_t *object;

    if(!(root = json_loadb(buffer, length, 0, &error))) {
        fprintf(stderr, "[-] json error: on line %d: %s\n", error.line, error.text);
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
    pannel_t *pannel = NULL;
    int n;

    if(!lws_get_protocol(wsi))
        return 0;

    pannel = (pannel_t *) lws_get_protocol(wsi)->user;

    if(reason == LWS_CALLBACK_ESTABLISHED) {
        printf("[+] new connection\n");
        pss->len = -1;

        unsigned char message[LWS_PRE + 1 + 4096];
        unsigned char *p = &message[LWS_PRE];

        printf("[+] sending current color [%d, %d, %d]\n", pannel->color.red, pannel->color.green, pannel->color.blue);

        json_t *root = json_object();
        json_object_set_new(root, "type", json_string("initial"));
        json_object_set_new(root, "red", json_integer(pannel->color.red));
        json_object_set_new(root, "green", json_integer(pannel->color.green));
        json_object_set_new(root, "blue", json_integer(pannel->color.blue));

        char *output = json_dumps(root, JSON_COMPACT);
        size_t length = strlen(output);
        json_decref(root);

        memcpy(p, output, length);
        free(output);

        lws_write(wsi, p, length, LWS_WRITE_TEXT);

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

            if(color_json(pss->buf + LWS_PRE, pss->len, &pannel->color))
                arduino_frame(pannel);
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

static void sighandler(int signal) {
    // got a signal
    printf("\n[+] signal intercepted: %d\n", signal);

    // setting exit code value
    stop_requested = 128 + signal;
    printf("[+] requesting shutdown with code: %d\n", stop_requested);
}

static int signal_intercept(int signal, void (*function)(int)) {
    struct sigaction sig;
    int ret;

    sigemptyset(&sig.sa_mask);
    sig.sa_handler = function;
    sig.sa_flags = 0;

    if((ret = sigaction(signal, &sig, NULL)) == -1)
        diep("sigaction");

    return ret;
}

int main(int argc, char **argv) {
    int port = 7681;
    struct lws_context *context;
    int listen_port = port;
    struct lws_context_creation_info info;
    char *interface = DEFAULT_INTERFACE;
    pannel_t pannel;

    printf("[+] initializing server\n");

    memset(&info, 0, sizeof(info));
    memset(&pannel, 0, sizeof(pannel_t));

    // set protocol user pointer
    protocols[0].user = &pannel;

    info.port = listen_port;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.extensions = exts;

    // signal handling
    signal_intercept(SIGINT, sighandler);

    if((context = lws_create_context(&info)) == NULL) {
        lwsl_err("libwebsocket init failed\n");
        exit(EXIT_FAILURE);
    }

    // socket initialization
    if(argc > 1)
        interface = argv[1];

    printf("[+] initializing frame\n");
    printf("[+] binding interface: %s\n", interface);

    if(!(socket_connect(&pannel, interface, dstaddr))) {
        fprintf(stderr, "[-] could not initialize frame\n");
        exit(EXIT_FAILURE);
    }

    int n = 1;

    printf("[+] waiting for clients\n");

    while(n >= 0 && !stop_requested)
        n = lws_service(context, 10);

    lws_context_destroy(context);

    return stop_requested;
}
