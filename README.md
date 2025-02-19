# pactis
Pactis is a lightweight and efficient Rust library for packet parsing
# Paccel

Paccel is a lightweight and efficient Rust library for packet parsing and processing. Designed with performance in mind, Paccel allows you to work with multiple layers of the network stack while keeping error handling robust and resource usage minimal.

## Features

- **Zero-Copy Design:**
  - Minimizes memory allocations
  - Uses borrowed types (`&str`, `&[u8]`) wherever possible
  - Avoids unnecessary owned types like `String` and `PathBuf`

- **Layered Architecture:**  
  Protocol processors for multiple network layers:
  - **Datalink Layer:**
    - ARP (Address Resolution Protocol)
  - **Network Layer:**
    - IPv4 (Internet Protocol version 4)
    - IPv6 (Internet Protocol version 6)
    - ICMP (Internet Control Message Protocol)
    - ICMPv6
    - IGMP (Internet Group Management Protocol)
  - **Application Layer:**
    - DNS (Domain Name System)

- **Robust Error Handling:**
  - Custom error types for each layer
  - No unwrap() or expect() calls in production code
  - Proper error propagation using the `?` operator
  - Detailed error messages for debugging

- **Comprehensive Validation:**
  Each protocol processor implements:
  - `can_parse(&Packet) -> bool`: Quick packet-type identification
  - `is_valid(&Packet) -> bool`: Packet integrity verification
  - `parse(&mut Packet) -> Result<T, LayerError>`: Full packet parsing

- **Extensive Testing:**
  - Unit tests for all protocol processors
  - Integration tests for multi-layer parsing
  - Test coverage for edge cases and error conditions
  - Fuzz testing for robustness

## Installation

Add Paccel to your project by including it in your `Cargo.toml`:

## Protocol Support Details

### Datalink Layer

#### ARP
- Supports both requests and replies
- Hardware type validation
- Protocol type validation
- MAC address parsing

### Network Layer

#### IPv4
- Header checksum validation
- Fragment handling
- Options parsing
- Total length verification

#### IPv6
- Fixed header parsing
- Extension headers support
- Flow label handling
- Payload length verification

#### ICMP/ICMPv6
- Message type validation
- Checksum verification
- Echo request/reply support
- Error message parsing

#### IGMP
- Version 1, 2, and 3 support
- Membership queries
- Membership reports
- Leave group messages

### Application Layer

#### DNS
- Query and response parsing
- Resource record handling
- Name compression support
- EDNS0 extensions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

### Development Guidelines

1. Follow Rust best practices
2. Avoid unwrap() and expect() in production code
3. Add tests for new features
4. Document public APIs
5. Run clippy and rustfmt before submitting PRs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by various packet parsing libraries in the Rust ecosystem
- Built with modern Rust practices and zero-copy principles
- Designed for performance and safety

## Version History

- 0.1.0
  - Initial release
  - Basic protocol support
  - Core architecture implementation
