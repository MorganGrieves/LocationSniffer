#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <signal.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <stddef.h>
#include <fcntl.h>

#define ETH_HEADER_SIZE 14

/*
 * В следующих сериях:
    3. Написать для rarp, ipv6
    4. Разделить на функции
    5. Заменить gethostbyname на getaddrinfo
    7. грамотное программирование
    8. заменить возвраты на EXIT_FAILURE
    9. привести к единому стилю кода
    10. проверить обработку ошибок
    11. добавить readme
    13. Заменить atoi на strtol
    14. тесты
    15. таймер
*/

FILE *tmp;
pcap_t *handle;

struct location {
    char status[10];
    char message[25];
    char continent[25];
    char country[60];
    char regionName[90];
    char city[90];
    char district[90];
    char timezone[50];
    char currency[10];
    char organization_name[100];
    char query[50];
    bool proxy;
    bool mobile;
} loc_info;

struct api_limits {
    long X_Rl;
    long X_Ttl;
} api_lim;

struct memory {
    char *response;
    size_t size;
};

void sigint_signal(int sig)
{
    if (sig == SIGINT) {
        pcap_close(handle);
        _exit(1);
    }
}

/* ****** file operations ****** */
/*! \brief      insert ip address to the end of tmp file, -1 - error, 0 - success
 *  \param s    ip address string
 */
int insert(const char *s)
{
    if (fseek(tmp, 0L, SEEK_END) != 0) {
        printf("Error: fseek push error: %s\n", strerror(errno));
        return -1;
    }
    
    if (fputs(s, tmp) == EOF) {
        if (fseek(tmp, 0L, SEEK_SET) != 0) {
            printf("Error: fseek push error: %s\n", strerror(errno));
            return -1;
        }
        printf("Error: unable to save %s\n", s);
        return -1;
    }

    if (fseek(tmp, 0L, SEEK_SET) != 0) {
        printf("Error: fseek push error: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/*! \brief      check out ip address in tmp file, -1 - error, 0 - false, 1 - true
 *  \param s    ip address string
 */
int contains(char *s)
{
    const char separator[2] = "\n";
    char line[40];
    while (!feof(tmp)) {
        if (fgets(line, sizeof(line), tmp)) {
            line[strcspn(line, separator)] = 0;
            if (strcmp(line, s) == 0) {
                if (fseek(tmp, 0L, SEEK_SET) != 0) {
                    printf("Error: fseek contains error: %s\n", strerror(errno));
                    return -1;
                }
                return 1;
            }
        }
    }

    if (fseek(tmp, 0, SEEK_SET) != 0) {
        printf("Error: fseek contains error: %s\n", strerror(errno));
        return -1;
    }
    
    return 0;
}
/* ********************** */

/*! \brief            check out ip address in tmp file
 *  \param  req_lim   api request limit
 *  \param  tim_lim   api time limit
 */
void set_limits(int req_lim, int tim_lim)
{
    api_lim.X_Rl = req_lim;
    api_lim.X_Ttl = tim_lim + 1;
}

/*! \brief          there are reserved ip addresses, check if it is, -1 - error, 0 - false, 1 - true
 *  \param  ip_v    ipv4 or ipv6(unsupported)
 *  \param  ip      ip addresses to check
 */
int is_reserved_ip(int ip_v, char *ip)
{
    int ip4_nums[4];
    
    switch (ip_v) {
        case AF_INET:
            sscanf(ip, "%d.%d.%d.%d", &ip4_nums[0], &ip4_nums[1], &ip4_nums[2], &ip4_nums[3]);
            
            //0.0.0.0–0.255.255.255 (16 777 216 IP addresses)
            if ((ip4_nums[0] == 0)
                && (ip4_nums[1] >= 0 && ip4_nums[1] < 256) 
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //10.0.0.0 – 10.255.255.255 (16,777,216 IP addresses)
            if ((ip4_nums[0] == 10) 
                && (ip4_nums[1] >= 0 && ip4_nums[1] < 256)
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //127.0.0.0–127.255.255.255 (16,777,216 IP addresses)
            if ((ip4_nums[0] == 127)
                && (ip4_nums[1] >= 0 && ip4_nums[1] < 256)
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //169.254.0.0–169.254.255.255 (65,536 IP addresses)
            if ((ip4_nums[0] == 169)
                && (ip4_nums[1] == 254) 
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //172.16.0.0 – 172.31.255.255 (1,048,576 IP addresses)
            if (ip4_nums[0] == 172 
                && ip4_nums[1] >= 16 && ip4_nums[1] < 32
                && ip4_nums[2] >= 0 && ip4_nums[2] < 256 
                && ip4_nums[3] >= 0 && ip4_nums[3] < 256) 
                return 1;
            
            //192.0.0.0–192.0.0.255 (256 IP addresses)
            if ((ip4_nums[0] == 192) 
                && (ip4_nums[1] == 0)
                && (ip4_nums[2] == 0) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //192.0.2.0–192.0.2.255 (256 IP addresses)
            if ((ip4_nums[0] == 192) 
                && (ip4_nums[1] == 0)
                && (ip4_nums[2] == 2) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //192.88.99.0–192.88.99.255 (256 IP addresses)
            if ((ip4_nums[0] == 192) 
                && (ip4_nums[1] == 88)
                && (ip4_nums[2] == 99) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //192.168.0.0 – 192.168.255.255 (65,536 IP addresses)
            if ((ip4_nums[0] == 192)
                && (ip4_nums[1] == 168) 
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //198.18.0.0–198.19.255.255 (131,072 IP addresses)
            if ((ip4_nums[0] == 198)
                && (ip4_nums[1] >= 18 && ip4_nums[1] < 20) 
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;

            //198.51.100.0–198.51.100.255 (256 IP addresses)
            if ((ip4_nums[0] == 198)
                && (ip4_nums[1] == 51) 
                && (ip4_nums[2] == 100) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //203.0.113.0–203.0.113.255 (256 IP addresses)
            if ((ip4_nums[0] == 203)
                && (ip4_nums[1] == 0) 
                && (ip4_nums[2] == 113) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //224.0.0.0–239.255.255.255 (268,435,456 IP addresses)
            if ((ip4_nums[0] >= 224 && ip4_nums[0] < 240)
                && (ip4_nums[1] >= 0 && ip4_nums[1] < 256) 
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //233.252.0.0-233.252.0.255 (256 IP addresses)
            if ((ip4_nums[0] == 233)
                && (ip4_nums[1] == 252) 
                && (ip4_nums[2] == 0) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 256)) 
                return 1;
            
            //240.0.0.0–255.255.255.254 (268,435,455 IP addresses)
            if ((ip4_nums[0] >= 240 && ip4_nums[0] < 255)
                && (ip4_nums[1] >= 0 && ip4_nums[1] < 256) 
                && (ip4_nums[2] >= 0 && ip4_nums[2] < 256) 
                && (ip4_nums[3] >= 0 && ip4_nums[3] < 255)) 
                return 1;
            
            //255.255.255.255
            if ((ip4_nums[0] == 255)
                && (ip4_nums[1] == 255) 
                && (ip4_nums[2] == 255) 
                && (ip4_nums[3] == 255)) 
                return 1;
                
            return 0;
            
//         case AF_INET6:
//             
//             break;
            
        default:
            return -1;
    }
}

/*! \brief             get header value, check if it is, -1 - error, 0 - false, 1 - true
 *  \param  headers    string with http headers
 *  \param  key        required header
 *  \param  res        return value by the key
 */
int return_value_by_key(const char *headers, const char *key, char *res)
{
    char *key_p = strstr(headers, key);
    
    if (NULL != key_p) {
        strncpy(res, strchr(key_p, ':') + 1, strchr(key_p, '\n') - strchr(key_p, ':'));
        return 0;
    }
    
    return -1;
}

/*! \brief  curl header callback */
size_t header_handle(char *data, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *) userdata;
    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (ptr == NULL)
        return 0;

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;
    return realsize;
}

/*! \brief  curl data callback */
size_t response_handle(void *data, size_t size, size_t nmemb, void  *userdata)
{
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *) userdata;
    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (ptr == NULL)
        return 0;

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;
    return realsize;
}

/*! \brief             send request, -1 - error, 0 - success
 *  \param  host       host for sending
 *  \param  data       return data
 */
int send_request(char *host, char **data)
{
    CURLcode res;
    CURL *curl_loc;
    
    struct memory response_chunk = {0};
    struct memory header_chunk = {0};
    
    curl_loc = curl_easy_init();
    if (curl_loc) {
        char xrl[40];
        char xttl[40];
        
        curl_easy_setopt(curl_loc, CURLOPT_URL, host);
        curl_easy_setopt(curl_loc, CURLOPT_WRITEDATA, (void *)&response_chunk);
        curl_easy_setopt(curl_loc, CURLOPT_WRITEFUNCTION, response_handle);
        curl_easy_setopt(curl_loc, CURLOPT_HEADERFUNCTION, header_handle);
        curl_easy_setopt(curl_loc, CURLOPT_HEADERDATA, (void *)&header_chunk);
        
        res = curl_easy_perform(curl_loc);
        if (res != CURLE_OK) {
            printf("Error: curl error: %s\n", curl_easy_strerror(res));
            return -1;
        }

        if (0 == return_value_by_key(header_chunk.response, "X-Rl", xrl)) {
            if (0 == return_value_by_key(header_chunk.response, "X-Ttl", xttl)) {
//                printf("parse request limit %s %d\n", xrl, atoi(xrl));
//                printf("parse time limit %s %d\n", xttl, atoi(xttl));
                set_limits(atoi(xrl), atoi(xttl));
            }
        }

        *data = response_chunk.response;

        curl_easy_cleanup(curl_loc);
        curl_loc = NULL;
    } else {
        perror("curl_loc initialization error\n");
        return -1;
    }

    return 0;
}

/*! \brief  print location */
void print_ip_location()
{
    printf("------ Response: ------\n");
    if (strcmp(loc_info.status, "success") == 0) {
        printf("status: %s\n", loc_info.status);    
        printf("continent: %s\n", loc_info.continent);
        printf("country: %s\n", loc_info.country);
        printf("regionName: %s\n", loc_info.regionName);
        printf("city: %s\n", loc_info.city);
        printf("timezone: %s\n", loc_info.timezone);
        printf("currency: %s\n", loc_info.currency);
        printf("org: %s\n", loc_info.organization_name);
        printf("proxy: %d\n", loc_info.proxy);
        printf("mobile: %d\n", loc_info.mobile);
        printf("ip: %s\n", loc_info.query);
    } else {
//        printf("ip failed: %s\n", loc_info.message);
    }
    printf("-----------------------\n");
}

/*! \brief  get location by ip, ipv4 and ipv6(unsupported) */
int get_location_by_ip(const char *ip)
{
    char host[1024];
    char *response;

    sprintf(host, "http://ip-api.com/line/%s?fields=status,message,continent,country,regionName,city,timezone,currency,org,mobile,proxy,query", ip);
    if (send_request(host, &response) < 0) {
        printf("Error: get location by ip\n");
        return -1;
    }
    
//     {
//         const char separator[3] = "\n";
//         char cresponse[1024];
//         char *line;
//         int cnt = 0;
//         
//         char *p1 = cresponse;
//         char *p2;
//         char newline[1000];
//         
//         strcpy(cresponse, response);
//         p2 = strstr(cresponse, separator);
//         
//         while (p2 != NULL) {
//             strncpy(newline, p1, p2 - p1);
//             newline[p2 - p1] = '\0';
//             
//             p1 = p2 + 1;
//             p2 = strstr(p1, separator);
//             printf("new line: %s\n", newline);
//         }     
//     }
    
    const char separator[3] = "\n";
    
    char *line_start = response;
    char *line_end;
    char line_buffer[250];
    
    line_end = strstr(response, separator);
    strncpy(line_buffer, line_start, line_end - line_start);
    line_buffer[line_end - line_start] = '\0';
    
    if (strcmp(line_buffer, "success") == 0) {
        strcpy(loc_info.status, "success");
        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.continent, line_buffer);
        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.country, line_buffer);
        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.regionName, line_buffer);
        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.city, line_buffer);
        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.timezone, line_buffer);
        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.currency, line_buffer);
                
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.organization_name, line_buffer);
        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        loc_info.proxy = (line_buffer == "true") ? true : false;
                
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        loc_info.mobile = (line_buffer == "true") ? true : false;
                        
        line_start = line_end + 1;
        line_end = strstr(line_start, separator);
        strncpy(line_buffer, line_start, line_end - line_start);
        line_buffer[line_end - line_start] = '\0';
        strcpy(loc_info.query, line_buffer);
//         strcpy(loc_info.status, "success");
// 
//         line = strtok(NULL, "\n");
//         strcpy(loc_info.continent, line);
// 
//         line = strtok(NULL, "\n");
//         strcpy(loc_info.country, line);
// 
//         line = strtok(NULL, "\n");
//         strcpy(loc_info.regionName, line);
// 
//         line = strtok(NULL, "\n");
//         strcpy(loc_info.city, line);
// 
//         line = strtok(NULL, "\n");
//         strcpy(loc_info.timezone, line);
// 
//         line = strtok(NULL, "\n");
//         strcpy(loc_info.currency, line);
// 
//         line = strtok(NULL, "\n");
//         printf("org: %s\n", line);
//         strcpy(loc_info.organization_name, line);
//         
//         line = strtok(NULL, "\n");
//         loc_info.proxy = (line == "true") ? true : false;
// 
//         line = strtok(NULL, "\n");
//         loc_info.mobile = (line == "true") ? true : false;
// 
//         line = strtok(NULL, "\n");
//         strcpy(loc_info.query, line);
    } else {
        strcpy(loc_info.status, "fail");
 
//         line = strtok(NULL, "\n");
//         printf("ERROR: %s\n", line);
//         strcpy(loc_info.message, line);

        return -1;
    }

    print_ip_location();
    
    return 0;
}

/*! \brief  capture packet and proccess it */
void my_packet_handler(const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_arp *arp_packet;
    struct ether_header *eth_header;
    struct ip *ip_header;
    char ip_src[100];
    char ip_dst[100];
    struct sockaddr_in h;

    eth_header = (struct ether_header *) packet;
    arp_packet = (struct ether_arp *) (packet + ETH_HEADER_SIZE);
    ip_header = (struct ip *)(packet + ETH_HEADER_SIZE);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        h.sin_family = ip_header->ip_v;
        h.sin_addr = ip_header->ip_src;
        h.sin_port = 0;

        if (ip_header->ip_v == 4 && inet_ntop(AF_INET, &ip_header->ip_src, ip_src, sizeof(ip_src)) != NULL) {
            if (!contains(ip_src)) {
                if (is_reserved_ip(AF_INET, ip_src)) {
                    printf("-----------------------------------\n");
                    printf("ip %s reserved for private networks\n", ip_src); 
                    printf("-----------------------------------\n");               
                    strcat(ip_src, "\n");
                    insert(ip_src);
                    return;
                }
                
                if (get_location_by_ip(ip_src)) {
                    printf("Error: get location ip\n");
                }
                
                strcat(ip_src, "\n");
                insert(ip_src);
            }
        } else {
            printf("Error: IP translation error: version: %d\n", ip_header->ip_v);
        }

        if (ip_header->ip_v == 4 && inet_ntop(AF_INET, &ip_header->ip_dst, ip_dst, sizeof(ip_dst)) != NULL) {
            if (!contains(ip_dst)) {
                if (is_reserved_ip(AF_INET, ip_dst)) {
                    printf("-----------------------------------\n");
                    printf("ip %s reserved for private networks\n", ip_dst);   
                    printf("-----------------------------------\n");             
                    strcat(ip_dst, "\n");
                    insert(ip_dst);
                    return;
                }
                
                if (get_location_by_ip(ip_dst)) {
                    printf("ERROR\n");
                }
                
                strcat(ip_dst, "\n");
                insert(ip_dst);
            }
        } else {
            printf("IP translation error: version: %d\n", ip_header->ip_v);
        }
        
        /* here should be ipv6 processing AF_INET6 */
    }
//    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
//         printf("ARP\n");
//         printf ("Source: %d.%d.%d.%d\t\tDestination: %d.%d.%d.%d\n",
//             arp_packet->arp_spa[0],
//             arp_packet->arp_spa[1],
//             arp_packet->arp_spa[2],
//             arp_packet->arp_spa[3],
//             arp_packet->arp_tpa[0],
//             arp_packet->arp_tpa[1],
//             arp_packet->arp_tpa[2],
//             arp_packet->arp_tpa[3]);
//     } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
//         printf("Reverse ARP\n");
//     }
}

int main(int argc, char *argv[])
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr packet_header;
    char *filter = "";
    int ret_value;
    const u_char *packet;
    struct bpf_program fp; /*compiled filter */
    bpf_u_int32 netp; /* ip address of interface */
    bpf_u_int32 maskp; /* subnet mask of interface */

//    if (argc < 2) {
//        fprintf("Usage: %s host...\n", argv[0]);
//        exit(EXIT_FAILURE);
//    }

    api_lim.X_Rl = -1;
    api_lim.X_Ttl = -1;

    tmp = tmpfile();

    if (!tmp) {
        printf("Error: Cannot open temporary file\n");
        exit(EXIT_FAILURE);
    }

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error: finding device: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(
        device,
        BUFSIZ,
        0,
        0,
        error_buffer
    );
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sigint_signal);    
    
    if (pcap_datalink(handle) != DLT_EN10MB) {
        printf("Error: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(device, &netp, &maskp, error_buffer) == -1) {
        printf("Error: %s", error_buffer);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter, 0, maskp) == -1) {
        printf("Error: %s", pcap_geterr);
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter (handle, &fp) == -1) {
        printf("Error: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_freecode(&fp);

    while (1) {
        packet = pcap_next(handle, &packet_header);
        if (packet) {
            my_packet_handler(&packet_header, packet);
        }
        
        if (api_lim.X_Rl == 0)
            if (api_lim.X_Ttl > 0)
                sleep(api_lim.X_Ttl);
    }
    
    return 0;
}
