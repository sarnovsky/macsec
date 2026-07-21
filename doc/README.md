# Lightweight MACsec Stack Documentation

This document describes the architecture, design principles and integration of the Lightweight MACsec Stack. It is intended for developers integrating the library into embedded systems or evaluating its implementation of IEEE 802.1AE MACsec and IEEE 802.1X MKA.

Unlike a protocol specification, this document focuses on how the library is organized internally, how packets are processed, and how applications interact with the public API. It complements the source code and examples rather than replacing them.

The documentation follows the same order in which the library operates. It starts with a high-level overview, continues with the path of an Ethernet frame through the stack, explains the initialization and key management process, and finally describes the platform adaptation layer required to port the library to a new target.

---

# 1. Introduction

**Lightweight MACsec Stack** is a compact implementation of IEEE 802.1AE MACsec with support for IEEE 802.1X MACsec Key Agreement (MKA). The library is designed primarily for resource-constrained embedded systems while remaining portable across different operating systems and hardware platforms.

The project was written with the following goals:

- Small memory footprint suitable for microcontrollers.
- Clear and well-defined public API.
- Platform-independent core implementation.
- Minimal external dependencies.
- Easy integration into existing Ethernet applications.
- Complete source code available under the MIT license.

The library separates protocol logic from platform-specific functionality. Cryptographic processing, MKA state machines and frame handling remain entirely platform independent, while hardware-specific operations such as Ethernet transmission, timing, random number generation and debugging are delegated to a small platform adaptation layer.

Although the implementation follows the IEEE specifications, the primary objective of the project is to provide a practical embedded MACsec implementation rather than a feature-complete desktop networking stack.

---

# 2. Learning Path

For readers who are new to the project, the documentation is intended to be read in the order shown below.

<p align="center">
    <img src="images/learning_path.svg" alt="Learning Path" width="700">
</p>

Each chapter builds upon the previous one:

1. **Architecture** introduces the major software components and explains how MACsec, MKA and the platform layer interact.

2. **Packet Journey** follows a single Ethernet frame through the complete processing pipeline, providing an intuitive overview before discussing implementation details.

3. **Integration** shows how the library fits into an embedded application and how it communicates with the surrounding software.

4. **Transmit Path**, **Receive Path** and **MKA Lifecycle** explain the internal processing performed by the library during normal operation.

5. **API and Configuration** describes the public configuration structures and runtime API used by the application.

6. **Porting Guide** summarizes the platform-specific functionality that must be implemented to run the library on a new hardware platform.

Experienced users may skip directly to the section relevant to their task, while new users are encouraged to follow the documentation sequentially for the best understanding of the overall design.

---

# 3. Architecture

The Lightweight MACsec Stack is organized into several independent layers. Each layer has a clearly defined responsibility, allowing the library to remain portable, easy to maintain and straightforward to integrate into existing applications.

<p align="center">
    <img src="images/architecture.svg" alt="Architecture" width="800">
</p>

At the highest level, the application communicates exclusively with the public MACsec API. The application is responsible for configuring the library, periodically calling the processing functions and transmitting or receiving Ethernet frames through the selected network interface.

Internally, the library consists of two major functional blocks.

The **MACsec** component implements the IEEE 802.1AE data plane. Its responsibilities include:

- Secure Association management.
- Packet Number (PN) handling.
- SecTAG generation and parsing.
- AES-GCM encryption and decryption.
- Integrity verification (ICV).
- Replay protection.

The **MKA** component implements the IEEE 802.1X MACsec Key Agreement protocol. It is responsible for:

- peer discovery,
- participant management,
- key server election,
- Secure Association Key (SAK) distribution,
- secure rekeying,
- periodic liveness monitoring.

Although these components operate independently, they cooperate through a well-defined interface. Whenever MKA establishes or updates a Secure Association Key, the new key is installed into the MACsec data plane. From that moment on, all protected traffic uses the newly negotiated Secure Association.

The cryptographic primitives used by both components are implemented separately from the protocol logic. This separation allows different cryptographic backends to be used without affecting the rest of the library.

Finally, all hardware-dependent functionality is isolated within the Platform Adaptation Layer. The core library has no direct knowledge of the operating system, Ethernet controller or hardware platform.

This layered organization keeps the implementation modular while allowing the same protocol code to run on a wide range of embedded targets.

---

# 4. Packet Journey

Understanding how a single Ethernet frame travels through the stack is the easiest way to understand the overall architecture.

<p align="center">
    <img src="images/packet_journey.svg" alt="Packet Journey" width="900">
</p>

The journey begins when the application produces a normal Ethernet frame. Depending on the current security state, the library either forwards the frame unchanged or applies MACsec protection before transmission.

When MACsec protection is enabled, the library performs the following operations:

1. Determine the active Secure Association.
2. Allocate the next Packet Number (PN).
3. Construct the SecTAG.
4. Encrypt the payload using AES-GCM.
5. Generate the Integrity Check Value (ICV).
6. Produce the protected Ethernet frame for transmission.

The protected frame is then transmitted by the platform-specific Ethernet driver without requiring any knowledge of the MACsec protocol.

On the receiving side, the reverse process is performed. Incoming frames are classified before further processing. Ordinary Ethernet traffic is passed directly to the application, while MACsec frames are authenticated, decrypted and validated before delivery.

If replay protection is enabled, the Packet Number is checked before accepting the frame. Frames outside the configured replay window or with an invalid Integrity Check Value are silently discarded.

During normal operation, MKA control frames follow a separate processing path. They are consumed internally by the MKA state machine and are never forwarded to the application. Their purpose is to establish and maintain the Secure Associations used by the MACsec data plane.

This separation between data traffic and control traffic keeps the public API simple while ensuring that key management remains completely transparent to the application.

---

# 5. Library Integration

The Lightweight MACsec Stack is designed to integrate into existing Ethernet applications with minimal changes to the surrounding software.

<p align="center">
    <img src="images/integration.svg" alt="Library Integration" width="900">
</p>

The application remains responsible for its normal networking tasks, including Ethernet driver initialization, network stack configuration and application logic. The MACsec library operates as an independent software component positioned between the application and the Ethernet driver.

From the application's perspective, the integration consists of four primary operations:

1. Configure the library.
2. Initialize the MACsec context.
3. Periodically execute the maintenance function.
4. Process transmitted and received Ethernet frames.

A typical application therefore performs the following sequence:

- Fill a `macsec_config_t` structure.
- Initialize a `macsec_ctx_t` instance using `macsec_init()`.
- Call `macsec_tick()` periodically from the main loop or operating system timer.
- Pass outgoing Ethernet frames through `macsec_output()`.
- Pass incoming Ethernet frames through `macsec_input()`.

The library does not create tasks, threads or timers internally. Scheduling is entirely controlled by the application, making the implementation equally suitable for bare-metal systems, RTOS environments and embedded Linux.

Likewise, the library performs no direct hardware access. Frame transmission and reception remain under full control of the application or Ethernet driver.

This design keeps the public API deterministic and allows the library to be integrated into existing projects without restructuring the surrounding software architecture.

---

# 6. MACsec Lifecycle

Once initialized, the library progresses through a well-defined sequence of operational states.

<p align="center">
    <img src="images/lifecycle.svg" alt="MACsec Lifecycle" width="850">
</p>

The lifecycle begins when the application calls `macsec_init()`. During initialization, the library validates the supplied configuration, initializes the cryptographic context and prepares the internal MACsec and MKA state machines.

The subsequent behavior depends on the selected operating mode.

In **Static SAK** mode, the Secure Association is installed immediately during initialization. The library enters the secured state without performing any key negotiation, allowing encrypted communication to begin as soon as Ethernet traffic is available.

In **MKA PSK** mode, the library enters the `WAIT_MKA` state. At this stage, MKA participants exchange MKPDUs, discover peers, elect a Key Server and negotiate a Secure Association Key (SAK). During this period, `macsec_tick()` drives the MKA state machine and schedules the transmission of control frames whenever required.

Once a valid SAK has been established, it is installed into the MACsec data plane. The library transitions into the `SECURED` state, after which outgoing frames are protected and incoming protected frames can be authenticated and decrypted.

Normal operation continues in the secured state. Periodic calls to `macsec_tick()` remain necessary to perform protocol maintenance, including participant liveness monitoring, key lifetime management and automatic rekeying when required.

If the active Secure Association changes, the MKA component transparently installs the new key into the MACsec engine. The application does not need to manage key transitions explicitly, and protected communication continues without interruption.

From the application's point of view, the lifecycle is intentionally simple: initialize the library once, call `macsec_tick()` periodically, and process Ethernet frames through the public API. All protocol-specific state management remains internal to the library.

---

# 7. Transmit Path

Outgoing Ethernet frames enter the library through the transmit API before being forwarded to the Ethernet driver.

<p align="center">
    <img src="images/transmit.svg" alt="Transmit Path" width="850">
</p>

The transmit path begins when the application provides a complete Ethernet frame to the library. Depending on the configured operating mode and the current security state, the frame is either forwarded unchanged or protected using MACsec.

If frame protection is required, the library performs the following operations:

1. Select the active transmit Secure Association.
2. Obtain the next Packet Number (PN).
3. Construct the MACsec SecTAG.
4. Generate the AES-GCM initialization vector (IV).
5. Encrypt the payload.
6. Compute the Integrity Check Value (ICV).
7. Assemble the final protected Ethernet frame.

The Packet Number is incremented for every transmitted protected frame and is never reused with the same Secure Association. This property is required by the MACsec specification and is essential for maintaining the security guarantees of AES-GCM.

The resulting frame is returned to the application, which remains responsible for transmitting it through the platform-specific Ethernet driver.

When operating in **Disabled** mode, or before a Secure Association has been established, protected transmission is not performed. Depending on the selected configuration, frames may either be transmitted without protection or deferred until secure communication becomes available.

The transmit path itself contains no platform-specific code and performs no direct hardware access. All operations are implemented entirely within the protocol layer.

---

# 8. Receive Path

Incoming Ethernet frames are delivered to the library immediately after reception from the Ethernet driver.

<p align="center">
    <img src="images/receive.svg" alt="Receive Path" width="850">
</p>

The first step of the receive path is frame classification. Based on the Ethernet EtherType, the library determines whether the received frame is:

- a normal Ethernet frame,
- a MACsec protected frame,
- an MKA control frame.

Ordinary Ethernet frames bypass the MACsec processing pipeline and may be delivered directly to the application.

MACsec protected frames undergo a series of validation steps before the original payload is released.

The library performs the following operations:

1. Parse the SecTAG.
2. Locate the corresponding receive Secure Association.
3. Verify the Packet Number against the replay window.
4. Authenticate the frame by verifying the Integrity Check Value (ICV).
5. Decrypt the protected payload.
6. Reconstruct the original Ethernet frame.

If any validation step fails, the frame is discarded immediately. Typical reasons include an unknown Secure Association, an invalid authentication tag or a replay protection violation.

The application receives only successfully authenticated frames. As a result, the application layer never processes modified or unauthenticated data.

Frames identified as MKA control traffic are handled differently. Rather than being forwarded to the application, they are consumed internally by the MKA state machine. Processing these frames updates peer information, maintains protocol state and may result in the installation of a new Secure Association Key.

Separating data traffic from control traffic keeps the application interface simple while allowing key management to operate transparently in the background.

---

# 9. MKA Control Flow

The MACsec Key Agreement (MKA) protocol operates independently from the data path and is responsible for establishing and maintaining Secure Associations between communicating peers.

<p align="center">
    <img src="images/sequence.svg" alt="MKA Control Flow" width="1000">
</p>

Unlike ordinary Ethernet traffic, MKA exchanges protocol control messages known as MACsec Key Agreement Protocol Data Units (MKPDUs). These frames are used exclusively for key management and are never forwarded to the application.

During normal operation the control flow consists of the following steps:

1. The application periodically calls `macsec_tick()`.
2. The internal MKA state machine updates timers and protocol state.
3. When required, the library requests transmission of an MKPDU.
4. The application transmits the generated control frame.
5. Incoming MKPDUs are passed to `macsec_input()`.
6. The MKA state machine validates and processes the received information.
7. If necessary, a new Secure Association Key (SAK) is generated or installed.
8. The MACsec data plane immediately begins using the updated Secure Association.

This process repeats continuously throughout the lifetime of the connection. Even after secure communication has been established, periodic MKPDUs remain necessary to maintain participant liveness, distribute updated security information and perform automatic rekeying.

The application does not need to interpret or construct MKA frames manually. All protocol encoding, decoding and state management are handled internally by the library.

---

# 10. Configuration

Before the library can be initialized, the application must provide a configuration describing the local device, operating mode and security parameters.

The primary configuration structure is `macsec_config_t`, which is supplied to `macsec_init()` during initialization.

Typical configuration parameters include:

| Parameter | Description |
|-----------|-------------|
| Local MAC Address | Ethernet MAC address of the local interface. |
| Port Identifier | Port number used when constructing the SCI. |
| Operating Mode | Disabled, Static SAK or MKA PSK. |
| CAK / CKN | Connectivity Association credentials used by MKA. |
| Static SAK | Secure Association Key used in Static SAK mode. |
| Replay Protection | Enables replay detection for received frames. |
| Replay Window | Acceptable Packet Number window size. |
| Key Server Priority | Priority used during MKA Key Server election. |
| Random Seed | Initial seed for the platform random generator, if required. |
| MKA Timing | Periodic transmission interval and protocol timing parameters. |

Not all configuration fields are required in every operating mode. For example, Static SAK mode does not require CAK or CKN, while MKA PSK mode does not require a preconfigured Secure Association Key.

After successful initialization, all runtime state is stored inside the `macsec_ctx_t` context structure. The application should treat this structure as opaque and access it only through the public API.

---

# 11. Porting Guide

The protocol implementation is completely platform independent. Hardware-specific functionality is provided through a small Platform Adaptation Layer implemented by the target application.

The required platform services are intentionally minimal.

### Random Number Generation

A cryptographically suitable random source is required for generating protocol values such as Message Identifiers (MI) and Secure Association Keys (SAKs).

### Time Base

The library requires a monotonically increasing time source used for protocol timers and periodic processing performed by `macsec_tick()`.

### Memory Management

Dynamic memory allocation is abstracted through platform functions. Applications may either use the standard C library or provide custom allocators suitable for embedded systems.

### Debug Output

Optional debug messages are routed through a platform-specific output function. Applications that do not require diagnostic output may disable this functionality entirely at compile time.

### Ethernet Driver

Frame transmission and reception remain the responsibility of the application. The Ethernet driver simply exchanges complete Ethernet frames with the MACsec library through the public API.

By isolating these services behind a small interface, the same protocol implementation can be reused on bare-metal systems, RTOS-based applications and embedded Linux platforms without modification.

---

# 12. Limitations

The Lightweight MACsec Stack focuses on providing a compact and portable implementation suitable for embedded systems. As a result, some features commonly found in desktop networking stacks are intentionally outside the scope of the project.

Current limitations include:

- Designed primarily for point-to-point Ethernet communication.
- Supports the operational modes described by the public API.
- Requires the application to provide Ethernet frame transmission and reception.
- Protocol scheduling is application driven through periodic calls to `macsec_tick()`.
- Platform-specific services (random number generation, timing, memory management and debugging) must be supplied by the application.

These limitations are intentional design decisions that keep the implementation simple, deterministic and suitable for resource-constrained environments.

Future versions of the library may extend the feature set while maintaining backward compatibility with the public API whenever practical.

---

# 13. Further Reading

The following documents provide additional background information on the protocols implemented by the library.

## IEEE Standards

- **IEEE 802.1AE** — Media Access Control (MAC) Security.
- **IEEE 802.1X** — Port-Based Network Access Control.
- **IEEE 802.1X-REV** — MACsec Key Agreement (MKA).

## Reference Implementations

- Linux MACsec subsystem.
- wpa_supplicant MKA implementation.

## Project Documentation

The project repository also contains:

- Source code documentation.
- Complete API reference in the header files.
- Unit tests covering protocol behavior.
- Integration examples for multiple platforms.

For the latest releases, examples and project updates, visit the project repository on GitHub.

---

# Conclusion

The Lightweight MACsec Stack provides a compact, portable and fully open-source implementation of IEEE 802.1AE MACsec together with IEEE 802.1X MACsec Key Agreement.

The project has been designed with embedded systems in mind, emphasizing simplicity, deterministic behavior and a clear separation between protocol logic and platform-specific code. This architecture allows the same core implementation to be reused across a wide range of hardware platforms with only a minimal platform adaptation layer.

Whether used for static Secure Associations or dynamic MKA-based key management, the library exposes a small and consistent public API while hiding the complexity of secure Ethernet communication behind a straightforward integration model.

Contributions, bug reports and feature suggestions are welcome and help improve the project for the entire embedded community.