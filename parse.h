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
    // 分析目的mac、源mac

    // 分析帧类型
    unsigned short e_type = seg_ether->type;
    /*switch(e_type)
    {
        case ETHER_TYPE_IP:
            printf("以太网帧类型：\tIP\n"); // */
            parse_ip(p_Ether + ETHER_LEN); /*
            break;
        case ETHER_TYPE_ARP:
            printf("以太网帧类型：\tARP\n");
            break;
        default:
            printf("以太网帧类型：\tUnknow\n");
            break;
    } //*/
}

/**
 分析IP头部
*/
void parse_ip(const char *p_IP)
{
    struct ip_header *seg_ip = (struct ip_header*)p_IP;

    char protocol = seg_ip->proto;
    switch(protocol)
    {
        case IP_ICMP:
            printf("IP报文类型：\tICMP\n");
            break;
        case IP_TCP:
            printf("IP报文类型：\tTCP\n");
            break;
        case IP_UDP:
            printf("IP报文类型：\tUDP\n");
            break;
        default:
            printf("IP报文类型：\tUnknow\n");
            break;
    }
}

