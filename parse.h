void start_parse(const char *p_package);
void parse_ether(const char *p_Ether);
void parse_ip(const char *p_IP);

/**
 开始解析
*/
void start_parse(const char *p_package)
{
    parse_ether(p_package);
}

/**
 分析Ethernet以太网包头
*/
void parse_ether(const char *p_Ether)
{
    struct ether_header *seg_ether = (struct ether_header *)p_Ether;

    printf("以太网帧信息\n");
    // 分析目的mac、源mac
    u_char *dest = seg_ether->host_dest;
    u_char *src = seg_ether->host_src;
    printf("  目的Mac地址：\t%02x:%02x:%02x:%02x:%02x:%02x\n", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);
    printf("  源Mac地址： \t%02x:%02x:%02x:%02x:%02x:%02x\n", src[0], src[1], src[2], src[3], src[4], src[5]);

    // 分析帧类型
    unsigned short int e_type = seg_ether->type;
    e_type = (e_type >> 8) | (e_type << 8);
    printf("  帧类型：\t");
    switch(e_type)
    {
        case ETHER_TYPE_IP:
            printf("IP\n");
            parse_ip(p_Ether + ETHER_LEN);
            break;
        case ETHER_TYPE_ARP:
            printf("ARP\n");
            break;
        default:
            printf("Unknow\n");
            break;
    }
}

/**
 分析IP头部
*/
void parse_ip(const char *p_IP)
{
    struct ip_header *seg_ip = (struct ip_header*)p_IP;

    printf("IP报文信息\n");

    /*  */
    char protocol = seg_ip->proto;
    printf("  报文类型：\t");
    switch(protocol)
    {
        case IP_ICMP:
            printf("ICMP\n");
            break;
        case IP_TCP:
            printf("TCP\n");
            break;
        case IP_UDP:
            printf("UDP\n");
            break;
        default:
            printf("Unknow\n");
            break;
    }
}

