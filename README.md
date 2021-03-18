# GunBound Server Recv() Intercept

Small library built to intercept encrypted and non-encrypted recv() server-side GunBound Game packets.

* Only received packets are intercepted.

Functions:

- void InstallHooks(): Apply the hooks at server memory addresses (addresses depends on server version).

- void Recv_EncryptedPackets(): Apply hook to intercept encrypted packets.
- void Recv_EncryptedFilter(): Receive the decrypted buffer from Recv_EncryptedPackets().

- void Recv_AllPackets(): Apply hook to intercept all non-encrypted packets.
- void Recv_AllPacketsFilter(): Receive the buffer from Recv_AllPackets().

Tested with GunBound Server version 3 (WC and S2).

Thanks to "ptr0x" for Assembly Analysis and "PEHook.h" Library.
