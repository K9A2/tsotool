/* tsotool dependencies */

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN 32
#endif

#ifndef HAVE_NETIF_MSG
enum
{
    NETIF_MSG_DRV = 0x0001,
    NETIF_MSG_PROBE = 0x0002,
    NETIF_MSG_LINK = 0x0004,
    NETIF_MSG_TIMER = 0x0008,
    NETIF_MSG_IFDOWN = 0x0010,
    NETIF_MSG_IFUP = 0x0020,
    NETIF_MSG_RX_ERR = 0x0040,
    NETIF_MSG_TX_ERR = 0x0080,
    NETIF_MSG_TX_QUEUED = 0x0100,
    NETIF_MSG_INTR = 0x0200,
    NETIF_MSG_TX_DONE = 0x0400,
    NETIF_MSG_RX_STATUS = 0x0800,
    NETIF_MSG_PKTDATA = 0x1000,
    NETIF_MSG_HW = 0x2000,
    NETIF_MSG_WOL = 0x4000,
};
#endif

#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

static void exit_bad_args(void)
{
    fprintf(stderr,
            "tsotool: bad command line argument(s)\n"
            "For more information run tsotool -h\n");
    exit(1);
}

typedef enum {
    CMDL_NONE,
    CMDL_BOOL,
    CMDL_S32,
    CMDL_U8,
    CMDL_U16,
    CMDL_U32,
    CMDL_U64,
    CMDL_BE16,
    CMDL_IP4,
    CMDL_STR,
    CMDL_FLAG,
    CMDL_MAC,
} cmdline_type_t;

struct cmdline_info
{
    const char *name;
    cmdline_type_t type;
    /* Points to int (BOOL), s32, u16, u32 (U32/FLAG/IP4), u64,
	 * char * (STR) or u8[6] (MAC).  For FLAG, the value accumulates
	 * all flags to be set. */
    void *wanted_val;
    void *ioctl_val;
    /* For FLAG, the flag value to be set/cleared */
    u32 flag_val;
    /* For FLAG, points to u32 and accumulates all flags seen.
	 * For anything else, points to int and is set if the option is
	 * seen. */
    void *seen_val;
};

struct flag_info
{
    const char *name;
    u32 value;
};

static const struct flag_info flags_msglvl[] = {
    {"drv", NETIF_MSG_DRV},
    {"probe", NETIF_MSG_PROBE},
    {"link", NETIF_MSG_LINK},
    {"timer", NETIF_MSG_TIMER},
    {"ifdown", NETIF_MSG_IFDOWN},
    {"ifup", NETIF_MSG_IFUP},
    {"rx_err", NETIF_MSG_RX_ERR},
    {"tx_err", NETIF_MSG_TX_ERR},
    {"tx_queued", NETIF_MSG_TX_QUEUED},
    {"intr", NETIF_MSG_INTR},
    {"tx_done", NETIF_MSG_TX_DONE},
    {"rx_status", NETIF_MSG_RX_STATUS},
    {"pktdata", NETIF_MSG_PKTDATA},
    {"hw", NETIF_MSG_HW},
    {"wol", NETIF_MSG_WOL},
};

struct off_flag_def
{
    const char *short_name;
    const char *long_name;
    const char *kernel_name;
    u32 get_cmd, set_cmd;
    u32 value;
    /* For features exposed through ETHTOOL_GFLAGS, the oldest
	 * kernel version for which we can trust the result.  Where
	 * the flag was added at the same time the kernel started
	 * supporting the feature, this is 0 (to allow for backports).
	 * Where the feature was supported before the flag was added,
	 * it is the version that introduced the flag.
	 */
    u32 min_kernel_ver;
};
static const struct off_flag_def off_flag_def[] = {
    {"rx", "rx-checksumming", "rx-checksum",
     ETHTOOL_GRXCSUM, ETHTOOL_SRXCSUM, ETH_FLAG_RXCSUM, 0},
    {"tx", "tx-checksumming", "tx-checksum-*",
     ETHTOOL_GTXCSUM, ETHTOOL_STXCSUM, ETH_FLAG_TXCSUM, 0},
    {"sg", "scatter-gather", "tx-scatter-gather*",
     ETHTOOL_GSG, ETHTOOL_SSG, ETH_FLAG_SG, 0},
    {"tso", "tcp-segmentation-offload", "tx-tcp*-segmentation",
     ETHTOOL_GTSO, ETHTOOL_STSO, ETH_FLAG_TSO, 0},
    {"ufo", "udp-fragmentation-offload", "tx-udp-fragmentation",
     ETHTOOL_GUFO, ETHTOOL_SUFO, ETH_FLAG_UFO, 0},
    {"gso", "generic-segmentation-offload", "tx-generic-segmentation",
     ETHTOOL_GGSO, ETHTOOL_SGSO, ETH_FLAG_GSO, 0},
    {"gro", "generic-receive-offload", "rx-gro",
     ETHTOOL_GGRO, ETHTOOL_SGRO, ETH_FLAG_GRO, 0},
    {"lro", "large-receive-offload", "rx-lro",
     0, 0, ETH_FLAG_LRO,
     KERNEL_VERSION(2, 6, 24)},
    {"rxvlan", "rx-vlan-offload", "rx-vlan-hw-parse",
     0, 0, ETH_FLAG_RXVLAN,
     KERNEL_VERSION(2, 6, 37)},
    {"txvlan", "tx-vlan-offload", "tx-vlan-hw-insert",
     0, 0, ETH_FLAG_TXVLAN,
     KERNEL_VERSION(2, 6, 37)},
    {"ntuple", "ntuple-filters", "rx-ntuple-filter",
     0, 0, ETH_FLAG_NTUPLE, 0},
    {"rxhash", "receive-hashing", "rx-hashing",
     0, 0, ETH_FLAG_RXHASH, 0},
};

struct feature_def
{
    char name[ETH_GSTRING_LEN];
    int off_flag_index; /* index in off_flag_def; negative if none match */
};

struct feature_defs
{
    size_t n_features;
    /* Number of features each offload flag is associated with */
    unsigned int off_flag_matched[ARRAY_SIZE(off_flag_def)];
    /* Name and offload flag index for each feature */
    struct feature_def def[0];
};

#define FEATURE_BITS_TO_BLOCKS(n_bits) DIV_ROUND_UP(n_bits, 32U)
#define FEATURE_WORD(blocks, index, field) ((blocks)[(index) / 32U].field)
#define FEATURE_FIELD_FLAG(index) (1U << (index) % 32U)
#define FEATURE_BIT_SET(blocks, index, field) \
    (FEATURE_WORD(blocks, index, field) |= FEATURE_FIELD_FLAG(index))
#define FEATURE_BIT_IS_SET(blocks, index, field) \
    (FEATURE_WORD(blocks, index, field) & FEATURE_FIELD_FLAG(index))

static long long
get_int_range(char *str, int base, long long min, long long max)
{
    long long v;
    char *endp;

    if (!str)
        exit_bad_args();
    errno = 0;
    v = strtoll(str, &endp, base);
    if (errno || *endp || v < min || v > max)
        exit_bad_args();
    return v;
}

static unsigned long long
get_uint_range(char *str, int base, unsigned long long max)
{
    unsigned long long v;
    char *endp;

    if (!str)
        exit_bad_args();
    errno = 0;
    v = strtoull(str, &endp, base);
    if (errno || *endp || v > max)
        exit_bad_args();
    return v;
}

static u32 get_u32(char *str, int base)
{
    return get_uint_range(str, base, 0xffffffff);
}

static void get_mac_addr(char *src, unsigned char *dest)
{
    int count;
    int i;
    int buf[ETH_ALEN];

    count = sscanf(src, "%2x:%2x:%2x:%2x:%2x:%2x",
                   &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
    if (count != ETH_ALEN)
        exit_bad_args();

    for (i = 0; i < count; i++)
    {
        dest[i] = buf[i];
    }
}

static void parse_generic_cmdline(struct cmd_context *ctx,
                                  int *changed,
                                  struct cmdline_info *info,
                                  unsigned int n_info)
{
    int argc = ctx->argc;
    char **argp = ctx->argp;
    int i, idx;
    int found;

    for (i = 0; i < argc; i++)
    {
        found = 0;
        for (idx = 0; idx < n_info; idx++)
        {
            if (!strcmp(info[idx].name, argp[i]))
            {
                found = 1;
                *changed = 1;
                if (info[idx].type != CMDL_FLAG &&
                    info[idx].seen_val)
                    *(int *)info[idx].seen_val = 1;
                i += 1;
                if (i >= argc)
                    exit_bad_args();
                switch (info[idx].type)
                {
                case CMDL_BOOL:
                {
                    int *p = info[idx].wanted_val;
                    if (!strcmp(argp[i], "on"))
                        *p = 1;
                    else if (!strcmp(argp[i], "off"))
                        *p = 0;
                    else
                        exit_bad_args();
                    break;
                }
                case CMDL_S32:
                {
                    s32 *p = info[idx].wanted_val;
                    *p = get_int_range(argp[i], 0,
                                       -0x80000000LL,
                                       0x7fffffff);
                    break;
                }
                case CMDL_U8:
                {
                    u8 *p = info[idx].wanted_val;
                    *p = get_uint_range(argp[i], 0, 0xff);
                    break;
                }
                case CMDL_U16:
                {
                    u16 *p = info[idx].wanted_val;
                    *p = get_uint_range(argp[i], 0, 0xffff);
                    break;
                }
                case CMDL_U32:
                {
                    u32 *p = info[idx].wanted_val;
                    *p = get_uint_range(argp[i], 0,
                                        0xffffffff);
                    break;
                }
                case CMDL_U64:
                {
                    u64 *p = info[idx].wanted_val;
                    *p = get_uint_range(
                        argp[i], 0,
                        0xffffffffffffffffLL);
                    break;
                }
                case CMDL_BE16:
                {
                    u16 *p = info[idx].wanted_val;
                    *p = cpu_to_be16(
                        get_uint_range(argp[i], 0,
                                       0xffff));
                    break;
                }
                case CMDL_IP4:
                {
                    u32 *p = info[idx].wanted_val;
                    struct in_addr in;
                    if (!inet_aton(argp[i], &in))
                        exit_bad_args();
                    *p = in.s_addr;
                    break;
                }
                case CMDL_MAC:
                    get_mac_addr(argp[i],
                                 info[idx].wanted_val);
                    break;
                case CMDL_FLAG:
                {
                    u32 *p;
                    p = info[idx].seen_val;
                    *p |= info[idx].flag_val;
                    if (!strcmp(argp[i], "on"))
                    {
                        p = info[idx].wanted_val;
                        *p |= info[idx].flag_val;
                    }
                    else if (strcmp(argp[i], "off"))
                    {
                        exit_bad_args();
                    }
                    break;
                }
                case CMDL_STR:
                {
                    char **s = info[idx].wanted_val;
                    *s = strdup(argp[i]);
                    break;
                }
                default:
                    exit_bad_args();
                }
                break;
            }
        }
        if (!found)
            exit_bad_args();
    }
}

static void flag_to_cmdline_info(const char *name, u32 value,
                                 u32 *wanted, u32 *mask,
                                 struct cmdline_info *cli)
{
    memset(cli, 0, sizeof(*cli));
    cli->name = name;
    cli->type = CMDL_FLAG;
    cli->flag_val = value;
    cli->wanted_val = wanted;
    cli->seen_val = mask;
}

static void
print_flags(const struct flag_info *info, unsigned int n_info, u32 value)
{
    const char *sep = "";

    while (n_info)
    {
        if (value & info->value)
        {
            printf("%s%s", sep, info->name);
            sep = " ";
            value &= ~info->value;
        }
        ++info;
        --n_info;
    }

    /* Print any unrecognised flags in hex */
    if (value)
        printf("%s%#x", sep, value);
}

static void dump_link_caps(const char *prefix, const char *an_prefix, u32 mask,
                           int link_mode_only);

static void dump_supported(struct ethtool_cmd *ep)
{
    u32 mask = ep->supported;

    fprintf(stdout, "	Supported ports: [ ");
    if (mask & SUPPORTED_TP)
        fprintf(stdout, "TP ");
    if (mask & SUPPORTED_AUI)
        fprintf(stdout, "AUI ");
    if (mask & SUPPORTED_BNC)
        fprintf(stdout, "BNC ");
    if (mask & SUPPORTED_MII)
        fprintf(stdout, "MII ");
    if (mask & SUPPORTED_FIBRE)
        fprintf(stdout, "FIBRE ");
    if (mask & SUPPORTED_Backplane)
        fprintf(stdout, "Backplane ");
    fprintf(stdout, "]\n");

    dump_link_caps("Supported", "Supports", mask, 0);
}

/* Print link capability flags (supported, advertised or lp_advertised).
 * Assumes that the corresponding SUPPORTED and ADVERTISED flags are equal.
 */
static void
dump_link_caps(const char *prefix, const char *an_prefix, u32 mask,
               int link_mode_only)
{
    static const struct
    {
        int same_line; /* print on same line as previous */
        u32 value;
        const char *name;
    } mode_defs[] = {
        {0, ADVERTISED_10baseT_Half, "10baseT/Half"},
        {1, ADVERTISED_10baseT_Full, "10baseT/Full"},
        {0, ADVERTISED_100baseT_Half, "100baseT/Half"},
        {1, ADVERTISED_100baseT_Full, "100baseT/Full"},
        {0, ADVERTISED_1000baseT_Half, "1000baseT/Half"},
        {1, ADVERTISED_1000baseT_Full, "1000baseT/Full"},
        {0, ADVERTISED_1000baseKX_Full, "1000baseKX/Full"},
        {0, ADVERTISED_2500baseX_Full, "2500baseX/Full"},
        {0, ADVERTISED_10000baseT_Full, "10000baseT/Full"},
        {0, ADVERTISED_10000baseKX4_Full, "10000baseKX4/Full"},
        {0, ADVERTISED_10000baseKR_Full, "10000baseKR/Full"},
        {0, ADVERTISED_20000baseMLD2_Full, "20000baseMLD2/Full"},
        {0, ADVERTISED_20000baseKR2_Full, "20000baseKR2/Full"},
        {0, ADVERTISED_40000baseKR4_Full, "40000baseKR4/Full"},
        {0, ADVERTISED_40000baseCR4_Full, "40000baseCR4/Full"},
        {0, ADVERTISED_40000baseSR4_Full, "40000baseSR4/Full"},
        {0, ADVERTISED_40000baseLR4_Full, "40000baseLR4/Full"},
        {0, ADVERTISED_56000baseKR4_Full, "56000baseKR4/Full"},
        {0, ADVERTISED_56000baseCR4_Full, "56000baseCR4/Full"},
        {0, ADVERTISED_56000baseSR4_Full, "56000baseSR4/Full"},
        {0, ADVERTISED_56000baseLR4_Full, "56000baseLR4/Full"},
    };
    int indent;
    int did1, new_line_pend, i;

    /* Indent just like the separate functions used to */
    indent = strlen(prefix) + 14;
    if (indent < 24)
        indent = 24;

    fprintf(stdout, "	%s link modes:%*s", prefix,
            indent - (int)strlen(prefix) - 12, "");
    did1 = 0;
    new_line_pend = 0;
    for (i = 0; i < ARRAY_SIZE(mode_defs); i++)
    {
        if (did1 && !mode_defs[i].same_line)
            new_line_pend = 1;
        if (mask & mode_defs[i].value)
        {
            if (new_line_pend)
            {
                fprintf(stdout, "\n");
                fprintf(stdout, "	%*s", indent, "");
                new_line_pend = 0;
            }
            did1++;
            fprintf(stdout, "%s ", mode_defs[i].name);
        }
    }
    if (did1 == 0)
        fprintf(stdout, "Not reported");
    fprintf(stdout, "\n");

    if (!link_mode_only)
    {
        fprintf(stdout, "	%s pause frame use: ", prefix);
        if (mask & ADVERTISED_Pause)
        {
            fprintf(stdout, "Symmetric");
            if (mask & ADVERTISED_Asym_Pause)
                fprintf(stdout, " Receive-only");
            fprintf(stdout, "\n");
        }
        else
        {
            if (mask & ADVERTISED_Asym_Pause)
                fprintf(stdout, "Transmit-only\n");
            else
                fprintf(stdout, "No\n");
        }

        fprintf(stdout, "	%s auto-negotiation: ", an_prefix);
        if (mask & ADVERTISED_Autoneg)
            fprintf(stdout, "Yes\n");
        else
            fprintf(stdout, "No\n");
    }
}

static int dump_ecmd(struct ethtool_cmd *ep)
{
    u32 speed;

    dump_supported(ep);
    dump_link_caps("Advertised", "Advertised", ep->advertising, 0);
    if (ep->lp_advertising)
        dump_link_caps("Link partner advertised",
                       "Link partner advertised", ep->lp_advertising,
                       0);

    fprintf(stdout, "	Speed: ");
    speed = ethtool_cmd_speed(ep);
    if (speed == 0 || speed == (u16)(-1) || speed == (u32)(-1))
        fprintf(stdout, "Unknown!\n");
    else
        fprintf(stdout, "%uMb/s\n", speed);

    fprintf(stdout, "	Duplex: ");
    switch (ep->duplex)
    {
    case DUPLEX_HALF:
        fprintf(stdout, "Half\n");
        break;
    case DUPLEX_FULL:
        fprintf(stdout, "Full\n");
        break;
    default:
        fprintf(stdout, "Unknown! (%i)\n", ep->duplex);
        break;
    };

    fprintf(stdout, "	Port: ");
    switch (ep->port)
    {
    case PORT_TP:
        fprintf(stdout, "Twisted Pair\n");
        break;
    case PORT_AUI:
        fprintf(stdout, "AUI\n");
        break;
    case PORT_BNC:
        fprintf(stdout, "BNC\n");
        break;
    case PORT_MII:
        fprintf(stdout, "MII\n");
        break;
    case PORT_FIBRE:
        fprintf(stdout, "FIBRE\n");
        break;
    case PORT_DA:
        fprintf(stdout, "Direct Attach Copper\n");
        break;
    case PORT_NONE:
        fprintf(stdout, "None\n");
        break;
    case PORT_OTHER:
        fprintf(stdout, "Other\n");
        break;
    default:
        fprintf(stdout, "Unknown! (%i)\n", ep->port);
        break;
    };

    fprintf(stdout, "	PHYAD: %d\n", ep->phy_address);
    fprintf(stdout, "	Transceiver: ");
    switch (ep->transceiver)
    {
    case XCVR_INTERNAL:
        fprintf(stdout, "internal\n");
        break;
    case XCVR_EXTERNAL:
        fprintf(stdout, "external\n");
        break;
    default:
        fprintf(stdout, "Unknown!\n");
        break;
    };

    fprintf(stdout, "	Auto-negotiation: %s\n",
            (ep->autoneg == AUTONEG_DISABLE) ? "off" : "on");

    if (ep->port == PORT_TP)
    {
        fprintf(stdout, "	MDI-X: ");
        if (ep->eth_tp_mdix_ctrl == ETH_TP_MDI)
        {
            fprintf(stdout, "off (forced)\n");
        }
        else if (ep->eth_tp_mdix_ctrl == ETH_TP_MDI_X)
        {
            fprintf(stdout, "on (forced)\n");
        }
        else
        {
            switch (ep->eth_tp_mdix)
            {
            case ETH_TP_MDI:
                fprintf(stdout, "off");
                break;
            case ETH_TP_MDI_X:
                fprintf(stdout, "on");
                break;
            default:
                fprintf(stdout, "Unknown");
                break;
            }
            if (ep->eth_tp_mdix_ctrl == ETH_TP_MDI_AUTO)
                fprintf(stdout, " (auto)");
            fprintf(stdout, "\n");
        }
    }

    return 0;
}

static char *unparse_wolopts(int wolopts)
{
    static char buf[16];
    char *p = buf;

    memset(buf, 0, sizeof(buf));

    if (wolopts)
    {
        if (wolopts & WAKE_PHY)
            *p++ = 'p';
        if (wolopts & WAKE_UCAST)
            *p++ = 'u';
        if (wolopts & WAKE_MCAST)
            *p++ = 'm';
        if (wolopts & WAKE_BCAST)
            *p++ = 'b';
        if (wolopts & WAKE_ARP)
            *p++ = 'a';
        if (wolopts & WAKE_MAGIC)
            *p++ = 'g';
        if (wolopts & WAKE_MAGICSECURE)
            *p++ = 's';
    }
    else
    {
        *p = 'd';
    }

    return buf;
}

static int dump_wol(struct ethtool_wolinfo *wol)
{
    fprintf(stdout, "	Supports Wake-on: %s\n",
            unparse_wolopts(wol->supported));
    fprintf(stdout, "	Wake-on: %s\n",
            unparse_wolopts(wol->wolopts));
    if (wol->supported & WAKE_MAGICSECURE)
    {
        int i;
        int delim = 0;
        fprintf(stdout, "        SecureOn password: ");
        for (i = 0; i < SOPASS_MAX; i++)
        {
            fprintf(stdout, "%s%02x", delim ? ":" : "", wol->sopass[i]);
            delim = 1;
        }
        fprintf(stdout, "\n");
    }

    return 0;
}

struct feature_state
{
    u32 off_flags;
    struct ethtool_gfeatures features;
};

static void dump_one_feature(const char *indent, const char *name,
                             const struct feature_state *state,
                             const struct feature_state *ref_state,
                             u32 index)
{
    if (ref_state &&
        !(FEATURE_BIT_IS_SET(state->features.features, index, active) ^
          FEATURE_BIT_IS_SET(ref_state->features.features, index, active)))
        return;

    printf("%s%s: %s%s\n",
           indent, name,
           FEATURE_BIT_IS_SET(state->features.features, index, active) ? "on" : "off",
           (!FEATURE_BIT_IS_SET(state->features.features, index, available) ||
            FEATURE_BIT_IS_SET(state->features.features, index,
                               never_changed))
               ? " [fixed]"
               : (FEATURE_BIT_IS_SET(state->features.features, index, requested) ^
                  FEATURE_BIT_IS_SET(state->features.features, index, active))
                     ? (FEATURE_BIT_IS_SET(state->features.features, index, requested)
                            ? " [requested on]"
                            : " [requested off]")
                     : "");
}

static int linux_version_code(void)
{
    struct utsname utsname;
    unsigned version, patchlevel, sublevel = 0;

    if (uname(&utsname))
        return -1;
    if (sscanf(utsname.release, "%u.%u.%u", &version, &patchlevel, &sublevel) < 2)
        return -1;
    return KERNEL_VERSION(version, patchlevel, sublevel);
}

static void dump_features(const struct feature_defs *defs,
                          const struct feature_state *state,
                          const struct feature_state *ref_state)
{
    int kernel_ver = linux_version_code();
    u32 value;
    int indent;
    int i, j;

    for (i = 0; i < ARRAY_SIZE(off_flag_def); i++)
    {
        /* Don't show features whose state is unknown on this
		 * kernel version
		 */
        if (defs->off_flag_matched[i] == 0 &&
            off_flag_def[i].get_cmd == 0 &&
            kernel_ver < off_flag_def[i].min_kernel_ver)
            continue;

        value = off_flag_def[i].value;

        /* If this offload flag matches exactly one generic
		 * feature then it's redundant to show the flag and
		 * feature states separately.  Otherwise, show the
		 * flag state first.
		 */
        if (defs->off_flag_matched[i] != 1 &&
            (!ref_state ||
             (state->off_flags ^ ref_state->off_flags) & value))
        {
            printf("%s: %s\n",
                   off_flag_def[i].long_name,
                   (state->off_flags & value) ? "on" : "off");
            indent = 1;
        }
        else
        {
            indent = 0;
        }

        /* Show matching features */
        for (j = 0; j < defs->n_features; j++)
        {
            if (defs->def[j].off_flag_index != i)
                continue;
            if (defs->off_flag_matched[i] != 1)
                /* Show all matching feature states */
                dump_one_feature(indent ? "\t" : "",
                                 defs->def[j].name,
                                 state, ref_state, j);
            else
                /* Show full state with the old flag name */
                dump_one_feature("", off_flag_def[i].long_name,
                                 state, ref_state, j);
        }
    }

    /* Show all unmatched features that have non-null names */
    for (j = 0; j < defs->n_features; j++)
        if (defs->def[j].off_flag_index < 0 && defs->def[j].name[0])
            dump_one_feature("", defs->def[j].name,
                             state, ref_state, j);
}

static struct ethtool_gstrings *
get_stringset(struct cmd_context *ctx, enum ethtool_stringset set_id,
              ptrdiff_t drvinfo_offset, int null_terminate)
{
    struct
    {
        struct ethtool_sset_info hdr;
        u32 buf[1];
    } sset_info;
    struct ethtool_drvinfo drvinfo;
    u32 len, i;
    struct ethtool_gstrings *strings;

    sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
    sset_info.hdr.reserved = 0;
    sset_info.hdr.sset_mask = 1ULL << set_id;
    if (send_ioctl(ctx, &sset_info) == 0)
    {
        len = sset_info.hdr.sset_mask ? sset_info.hdr.data[0] : 0;
    }
    else if (errno == EOPNOTSUPP && drvinfo_offset != 0)
    {
        /* Fallback for old kernel versions */
        drvinfo.cmd = ETHTOOL_GDRVINFO;
        if (send_ioctl(ctx, &drvinfo))
            return NULL;
        len = *(u32 *)((char *)&drvinfo + drvinfo_offset);
    }
    else
    {
        return NULL;
    }

    strings = calloc(1, sizeof(*strings) + len * ETH_GSTRING_LEN);
    if (!strings)
        return NULL;

    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = set_id;
    strings->len = len;
    if (len != 0 && send_ioctl(ctx, strings))
    {
        free(strings);
        return NULL;
    }

    if (null_terminate)
        for (i = 0; i < len; i++)
            strings->data[(i + 1) * ETH_GSTRING_LEN - 1] = 0;

    return strings;
}

static struct feature_defs *get_feature_defs(struct cmd_context *ctx)
{
    struct ethtool_gstrings *names;
    struct feature_defs *defs;
    u32 n_features;
    int i, j;

    names = get_stringset(ctx, ETH_SS_FEATURES, 0, 1);
    if (names)
    {
        n_features = names->len;
    }
    else if (errno == EOPNOTSUPP || errno == EINVAL)
    {
        /* Kernel doesn't support named features; not an error */
        n_features = 0;
    }
    else if (errno == EPERM)
    {
        /* Kernel bug: ETHTOOL_GSSET_INFO was privileged.
		 * Work around it. */
        n_features = 0;
    }
    else
    {
        return NULL;
    }

    defs = malloc(sizeof(*defs) + sizeof(defs->def[0]) * n_features);
    if (!defs)
        return NULL;

    defs->n_features = n_features;
    memset(defs->off_flag_matched, 0, sizeof(defs->off_flag_matched));

    /* Copy out feature names and find those associated with legacy flags */
    for (i = 0; i < defs->n_features; i++)
    {
        memcpy(defs->def[i].name, names->data + i * ETH_GSTRING_LEN,
               ETH_GSTRING_LEN);
        defs->def[i].off_flag_index = -1;

        for (j = 0;
             j < ARRAY_SIZE(off_flag_def) &&
             defs->def[i].off_flag_index < 0;
             j++)
        {
            const char *pattern =
                off_flag_def[j].kernel_name;
            const char *name = defs->def[i].name;
            for (;;)
            {
                if (*pattern == '*')
                {
                    /* There is only one wildcard; so
					 * switch to a suffix comparison */
                    size_t pattern_len =
                        strlen(pattern + 1);
                    size_t name_len = strlen(name);
                    if (name_len < pattern_len)
                        break; /* name is too short */
                    name += name_len - pattern_len;
                    ++pattern;
                }
                else if (*pattern != *name)
                {
                    break; /* mismatch */
                }
                else if (*pattern == 0)
                {
                    defs->def[i].off_flag_index = j;
                    defs->off_flag_matched[j]++;
                    break;
                }
                else
                {
                    ++name;
                    ++pattern;
                }
            }
        }
    }

    free(names);
    return defs;
}

static struct feature_state *
get_features(struct cmd_context *ctx, const struct feature_defs *defs)
{
    struct feature_state *state;
    struct ethtool_value eval;
    int err, allfail = 1;
    u32 value;
    int i;

    state = malloc(sizeof(*state) +
                   FEATURE_BITS_TO_BLOCKS(defs->n_features) *
                       sizeof(state->features.features[0]));
    if (!state)
        return NULL;

    state->off_flags = 0;

    for (i = 0; i < ARRAY_SIZE(off_flag_def); i++)
    {
        value = off_flag_def[i].value;
        if (!off_flag_def[i].get_cmd)
            continue;
        eval.cmd = off_flag_def[i].get_cmd;
        err = send_ioctl(ctx, &eval);
        if (err)
        {
            fprintf(stderr,
                    "Cannot get device %s settings: %m\n",
                    off_flag_def[i].long_name);
        }
        else
        {
            if (eval.data)
                state->off_flags |= value;
            allfail = 0;
        }
    }

    eval.cmd = ETHTOOL_GFLAGS;
    err = send_ioctl(ctx, &eval);
    if (err)
    {
        perror("Cannot get device flags");
    }
    else
    {
        state->off_flags |= eval.data & ETH_FLAG_EXT_MASK;
        allfail = 0;
    }

    if (defs->n_features)
    {
        state->features.cmd = ETHTOOL_GFEATURES;
        state->features.size = FEATURE_BITS_TO_BLOCKS(defs->n_features);
        err = send_ioctl(ctx, &state->features);
        if (err)
            perror("Cannot get device generic features");
        else
            allfail = 0;
    }

    if (allfail)
    {
        free(state);
        return NULL;
    }

    return state;
}

static int do_gfeatures(struct cmd_context *ctx)
{
    struct feature_defs *defs;
    struct feature_state *features;
    
    defs = get_feature_defs(ctx);
    if (!defs)
    {
        perror("Cannot get device feature names");
        return 1;
    }

    fprintf(stdout, "Features for %s:\n", ctx->devname);

    features = get_features(ctx, defs);
    if (!features)
    {
        fprintf(stdout, "no feature info available\n");
        return 1;
    }

    dump_features(defs, features, NULL);
    return 0;
}

static int do_sfeatures(struct cmd_context *ctx)
{
    struct feature_defs *defs;
    int any_changed = 0, any_mismatch = 0;
    u32 off_flags_wanted = 0;
    u32 off_flags_mask = 0;
    struct ethtool_sfeatures *efeatures;
    struct cmdline_info *cmdline_features;
    struct feature_state *old_state, *new_state;
    struct ethtool_value eval;
    int err;
    int i, j;

    defs = get_feature_defs(ctx);
    if (!defs)
    {
        perror("Cannot get device feature names");
        return 1;
    }
    if (defs->n_features)
    {
        efeatures = malloc(sizeof(*efeatures) +
                           FEATURE_BITS_TO_BLOCKS(defs->n_features) *
                               sizeof(efeatures->features[0]));
        if (!efeatures)
        {
            perror("Cannot parse arguments");
            return 1;
        }
        efeatures->cmd = ETHTOOL_SFEATURES;
        efeatures->size = FEATURE_BITS_TO_BLOCKS(defs->n_features);
        memset(efeatures->features, 0,
               FEATURE_BITS_TO_BLOCKS(defs->n_features) *
                   sizeof(efeatures->features[0]));
    }
    else
    {
        efeatures = NULL;
    }

    /* Generate cmdline_info for legacy flags and kernel-named
	 * features, and parse our arguments.
	 */
    cmdline_features = calloc(ARRAY_SIZE(off_flag_def) + defs->n_features,
                              sizeof(cmdline_features[0]));
    if (!cmdline_features)
    {
        perror("Cannot parse arguments");
        return 1;
    }
    for (i = 0; i < ARRAY_SIZE(off_flag_def); i++)
        flag_to_cmdline_info(off_flag_def[i].short_name,
                             off_flag_def[i].value,
                             &off_flags_wanted, &off_flags_mask,
                             &cmdline_features[i]);
    for (i = 0; i < defs->n_features; i++)
        flag_to_cmdline_info(
            defs->def[i].name, FEATURE_FIELD_FLAG(i),
            &FEATURE_WORD(efeatures->features, i, requested),
            &FEATURE_WORD(efeatures->features, i, valid),
            &cmdline_features[ARRAY_SIZE(off_flag_def) + i]);
    parse_generic_cmdline(ctx, &any_changed, cmdline_features,
                          ARRAY_SIZE(off_flag_def) + defs->n_features);
    free(cmdline_features);

    if (!any_changed)
    {
        fprintf(stdout, "no features changed\n");
        return 0;
    }

    old_state = get_features(ctx, defs);
    if (!old_state)
        return 1;

    if (efeatures)
    {
        /* For each offload that the user specified, update any
		 * related features that the user did not specify and that
		 * are not fixed.  Warn if all related features are fixed.
		 */
        for (i = 0; i < ARRAY_SIZE(off_flag_def); i++)
        {
            int fixed = 1;

            if (!(off_flags_mask & off_flag_def[i].value))
                continue;

            for (j = 0; j < defs->n_features; j++)
            {
                if (defs->def[j].off_flag_index != i ||
                    !FEATURE_BIT_IS_SET(
                        old_state->features.features,
                        j, available) ||
                    FEATURE_BIT_IS_SET(
                        old_state->features.features,
                        j, never_changed))
                    continue;

                fixed = 0;
                if (!FEATURE_BIT_IS_SET(efeatures->features,
                                        j, valid))
                {
                    FEATURE_BIT_SET(efeatures->features,
                                    j, valid);
                    if (off_flags_wanted &
                        off_flag_def[i].value)
                        FEATURE_BIT_SET(
                            efeatures->features,
                            j, requested);
                }
            }

            if (fixed)
                fprintf(stderr, "Cannot change %s\n",
                        off_flag_def[i].long_name);
        }

        err = send_ioctl(ctx, efeatures);
        if (err < 0)
        {
            perror("Cannot set device feature settings");
            return 1;
        }
    }
    else
    {
        for (i = 0; i < ARRAY_SIZE(off_flag_def); i++)
        {
            if (!off_flag_def[i].set_cmd)
                continue;
            if (off_flags_mask & off_flag_def[i].value)
            {
                eval.cmd = off_flag_def[i].set_cmd;
                eval.data = !!(off_flags_wanted &
                               off_flag_def[i].value);
                err = send_ioctl(ctx, &eval);
                if (err)
                {
                    fprintf(stderr,
                            "Cannot set device %s settings: %m\n",
                            off_flag_def[i].long_name);
                    return 1;
                }
            }
        }

        if (off_flags_mask & ETH_FLAG_EXT_MASK)
        {
            eval.cmd = ETHTOOL_SFLAGS;
            eval.data = (old_state->off_flags & ~off_flags_mask &
                         ETH_FLAG_EXT_MASK);
            eval.data |= off_flags_wanted & ETH_FLAG_EXT_MASK;

            err = send_ioctl(ctx, &eval);
            if (err)
            {
                perror("Cannot set device flag settings");
                return 92;
            }
        }
    }

    /* Compare new state with requested state */
    new_state = get_features(ctx, defs);
    if (!new_state)
        return 1;
    any_changed = new_state->off_flags != old_state->off_flags;
    any_mismatch = (new_state->off_flags !=
                    ((old_state->off_flags & ~off_flags_mask) |
                     off_flags_wanted));
    for (i = 0; i < FEATURE_BITS_TO_BLOCKS(defs->n_features); i++)
    {
        if (new_state->features.features[i].active !=
            old_state->features.features[i].active)
            any_changed = 1;
        if (new_state->features.features[i].active !=
            ((old_state->features.features[i].active &
              ~efeatures->features[i].valid) |
             efeatures->features[i].requested))
            any_mismatch = 1;
    }
    if (any_mismatch)
    {
        if (!any_changed)
        {
            fprintf(stderr,
                    "Could not change any device features\n");
            return 1;
        }
        printf("Actual changes:\n");
        dump_features(defs, new_state, old_state);
    }

    return 0;
}

static int do_gset(struct cmd_context *ctx)
{
    int err;
    struct ethtool_cmd ecmd;
    struct ethtool_wolinfo wolinfo;
    struct ethtool_value edata;
    int allfail = 1;

    if (ctx->argc != 0)
        exit_bad_args();

    fprintf(stdout, "Settings for %s:\n", ctx->devname);

    ecmd.cmd = ETHTOOL_GSET;
    err = send_ioctl(ctx, &ecmd);
    if (err == 0)
    {
        err = dump_ecmd(&ecmd);
        if (err)
            return err;
        allfail = 0;
    }
    else if (errno != EOPNOTSUPP)
    {
        perror("Cannot get device settings");
    }

    wolinfo.cmd = ETHTOOL_GWOL;
    err = send_ioctl(ctx, &wolinfo);
    if (err == 0)
    {
        err = dump_wol(&wolinfo);
        if (err)
            return err;
        allfail = 0;
    }
    else if (errno != EOPNOTSUPP)
    {
        perror("Cannot get wake-on-lan settings");
    }

    edata.cmd = ETHTOOL_GMSGLVL;
    err = send_ioctl(ctx, &edata);
    if (err == 0)
    {
        fprintf(stdout, "	Current message level: 0x%08x (%d)\n"
                        "			       ",
                edata.data, edata.data);
        print_flags(flags_msglvl, ARRAY_SIZE(flags_msglvl),
                    edata.data);
        fprintf(stdout, "\n");
        allfail = 0;
    }
    else if (errno != EOPNOTSUPP)
    {
        perror("Cannot get message level");
    }

    edata.cmd = ETHTOOL_GLINK;
    err = send_ioctl(ctx, &edata);
    if (err == 0)
    {
        fprintf(stdout, "	Link detected: %s\n",
                edata.data ? "yes" : "no");
        allfail = 0;
    }
    else if (errno != EOPNOTSUPP)
    {
        perror("Cannot get link status");
    }

    if (allfail)
    {
        fprintf(stdout, "No data available\n");
        return 75;
    }
    return 0;
}

#ifndef TEST_ETHTOOL

int send_ioctl(struct cmd_context *ctx, void *cmd)
{
    ctx->ifr.ifr_data = cmd;
    return ioctl(ctx->fd, SIOCETHTOOL, &ctx->ifr);
}

#endif

static const struct option
{
    const char *opts;
    int want_device;

    int (*func)(struct cmd_context *);

    char *help;
    char *opthelp;
} args[] = {
    {"-k|--show-features|--show-offload", 1, do_gfeatures,
     "Get state of protocol offload and other features"},
    {"-K|--features|--offload", 1, do_sfeatures,
     "Set protocol offload and other features",
     "		FEATURE on|off ...\n"},
};