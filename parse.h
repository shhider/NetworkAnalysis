void start_parse(const char *p_package);
void parse_ether(const char *p_Ether);
void parse_ip(const char *p_IP);
void parse_tcp(const char *p_TCP);

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
    ether_header *seg_ether = (ether_header *)p_Ether;

    printf("以太网帧信息\n");
    // 分析目的mac、源mac
    u_char *dest = seg_ether->host_dest;
    u_char *src = seg_ether->host_src;
    printf("  目的Mac地址：\t%02x.%02x.%02x.%02x.%02x.%02x\n", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);
    printf("  源Mac地址： \t%02x.%02x.%02x.%02x.%02x.%02x\n", src[0], src[1], src[2], src[3], src[4], src[5]);

    // 分析帧类型
    u_short e_type = seg_ether->type;
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
    ip_header *seg_ip = (ip_header*)p_IP;
    printf("IP报文信息\n");

    u_char version = (seg_ip->ver_ihl) >> 4;
    printf("  版本号：\t%u\n", version);
    int header_len = ((seg_ip->ver_ihl) & 0x0f) * 4;
    printf("  首部长度：\t%d 字节\n", header_len);

    printf("  服务类型：\t%u\n", seg_ip->tos);

    u_short data_len = (u_short)((seg_ip->tlen) >> 8 | (seg_ip->tlen) << 8);
    printf("  总长度：\t%u 字节\n", data_len);

    u_short ident = (u_short)((seg_ip->ident) >> 8 | (seg_ip->ident) << 8);
    printf("  标识：\t%u\n", ident);

    printf("  标记：\t%u\n", (seg_ip->flags_fo) >> 5 & 0x0007 );
    u_short offset = (u_short)((seg_ip->flags_fo) >> 8 | (seg_ip->flags_fo) << 8) & 0x1fff;
    printf("  片偏移：\t%u\n", offset );

    printf("  寿命TTL：\t%u\n", seg_ip->ttl);

    u_short checksum = (u_short)((seg_ip->crc) >> 8 | (seg_ip->crc) << 8);
    printf("  校验和：\t0x%04x\n", checksum);

    //printf("  源IP地址：\t%u:%u:%u:%u\n", seg_ip->saddr.byte1, seg_ip->saddr.byte2, seg_ip->saddr.byte3, seg_ip->saddr.byte4);
    //printf("  目的IP地址：\t%u:%u:%u:%u\n", seg_ip->daddr.byte1, seg_ip->daddr.byte2, seg_ip->daddr.byte3, seg_ip->daddr.byte4);

    char protocol = seg_ip->proto;
    printf("  报文类型：\t");
    switch(protocol)
    {
        case IP_ICMP:
            printf("ICMP\n");
            break;
        case IP_TCP:
            printf("TCP\n");
            parse_tcp(p_IP + header_len);
            break;
        case IP_UDP:
            printf("UDP\n");
            break;
        default:
            printf("Unknow\n");
            break;
    }
}

void parse_tcp(const char *p_TCP)
{
    tcp_header *seg_tcp = (tcp_header*)p_TCP;
    printf("TCP报文信息：\n");

    u_short sport = (u_short)((seg_tcp->th_sport) >> 8 | (seg_tcp->th_sport) << 8);
    printf("  源端口：\t%u\n", sport);
    u_short dport = (u_short)((seg_tcp->th_dport) >> 8 | (seg_tcp->th_dport) << 8);
    printf("  目的端口：\t%u\n", dport);

    printf("  标志字段：\t");
    u_char flag = seg_tcp->th_flags;
    switch(flag)
    {
    case TH_FIN:
        printf("FIN = 1\n");
        break;
    case TH_SYN:
        printf("SYN = 1\n");
        break;
    case TH_RST:
        printf("RST = 1\n");
        break;
    case TH_PSH:
        printf("PSH = 1\n");
        break;
    case TH_ACK:
        printf("ACK = 1\n");
        break;
    case TH_URG:
        printf("URG = 1\n");
        break;
    default:
        printf("ERROR!\n");
        break;
    }

}

