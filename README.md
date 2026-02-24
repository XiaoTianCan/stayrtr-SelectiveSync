# Project Info

This project is built on the forked open-source [StayRTR project](https://github.com/bgp/stayrtr), aiming to implement the function of selectively synchronizing RPKI data to routers. It addresses the need for more flexible and targeted RPKI data distribution, and achieves this through two key extensions as follows:

- Extending the SLURM mechanism: This extension enables filtering of specific types of RPKI data. Supported filter types include IPv4 Prefix, IPv6 Prefix, and Router Key, allowing for precise control over the RPKI data that is processed and forwarded.

- Extending the RTR protocol: The Client can subscribe to specific types of RPKI data from the server via the Subscribe PDU. After a successful subscription, the server will only synchronize the subscribed types of RPKI data to the corresponding Client, reducing unnecessary data transmission and improving efficiency.

By integrating these two extensions into the StayRTR project, the solution provides a more refined and efficient RPKI data synchronization mechanism, which is particularly valuable for scenarios where routers require only specific RPKI data types to meet their operational needs.

# Related IETF Document
- https://datatracker.ietf.org/doc/draft-fu-sidrops-enhanced-slurm-filter/
- https://datatracker.ietf.org/doc/draft-geng-sidrops-rtr-selective-sync/

# Original README

Please see: [link](https://github.com/XiaoTianCan/stayrtr-SelectiveSync/blob/master/README-original.md)

## License

Licensed under the BSD 3 License.
