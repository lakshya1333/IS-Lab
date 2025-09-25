# 5. As part of a project to enhance the security of communication in a peer-to-peer file
# sharing system, you are tasked with implementing a secure key exchange
# mechanism using the Diffie-Hellman algorithm. Each peer must establish a shared
# secret key with another peer over an insecure channel. Implement the DiffieHellman key exchange protocol, enabling peers to generate their public and private
# keys and securely compute the shared secret key. Measure the time taken for key
# generation and key exchange processes. 


import random
import time
import statistics


def measure_time(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, end - start

def generate_dh_keypair(p, g):
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(peer_public_key, own_private_key, p):
    shared_secret = pow(peer_public_key, own_private_key, p)
    return shared_secret

def diffie_hellman_exchange():
    print("DIFFIE-HELLMAN KEY EXCHANGE PROTOCOL")
    print("=" * 60)

    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

    g = 2

    print("DOMAIN PARAMETERS")
    print("-" * 40)
    print(f"Prime p: {hex(p)}")
    print(f"Generator g: {g}")
    print(f"Prime size: {p.bit_length()} bits")

    iterations = 10
    peer1_keygen_times = []
    peer2_keygen_times = []
    shared_secret_times = []

    print(f"\nRUNNING {iterations} KEY EXCHANGE ITERATIONS")
    print("-" * 40)

    for i in range(iterations):
        print(f"Iteration {i + 1}:")

        (peer1_private, peer1_public), peer1_time = measure_time(generate_dh_keypair, p, g)
        peer1_keygen_times.append(peer1_time)

        (peer2_private, peer2_public), peer2_time = measure_time(generate_dh_keypair, p, g)
        peer2_keygen_times.append(peer2_time)

        print(f"  Peer 1 private key: {hex(peer1_private)}")
        print(f"  Peer 1 public key: {hex(peer1_public)}")
        print(f"  Peer 2 private key: {hex(peer2_private)}")
        print(f"  Peer 2 public key: {hex(peer2_public)}")

        start_time = time.perf_counter()

        shared1 = compute_shared_secret(peer2_public, peer1_private, p)
        shared2 = compute_shared_secret(peer1_public, peer2_private, p)

        end_time = time.perf_counter()
        shared_secret_times.append(end_time - start_time)

        print(f"  Peer 1 computed shared secret: {hex(shared1)}")
        print(f"  Peer 2 computed shared secret: {hex(shared2)}")
        print(f"  Shared secrets match: {'YES' if shared1 == shared2 else 'NO'}")
        print(f"  Key generation time: {(peer1_time + peer2_time) * 1000:.3f} ms")
        print(f"  Shared secret computation: {(end_time - start_time) * 1000:.3f} ms")
        print()

    avg_peer1_keygen = statistics.mean(peer1_keygen_times) * 1000
    avg_peer2_keygen = statistics.mean(peer2_keygen_times) * 1000
    avg_total_keygen = statistics.mean([p1 + p2 for p1, p2 in zip(peer1_keygen_times, peer2_keygen_times)]) * 1000
    avg_shared_secret = statistics.mean(shared_secret_times) * 1000

    print("PERFORMANCE ANALYSIS")
    print("=" * 60)

    print(f"{'Operation':<25} {'Average Time (ms)':<20} {'Min (ms)':<15} {'Max (ms)':<15}")
    print("-" * 75)
    print(
        f"{'Peer 1 Key Generation':<25} {avg_peer1_keygen:<20.3f} {min(peer1_keygen_times) * 1000:<15.3f} {max(peer1_keygen_times) * 1000:<15.3f}")
    print(
        f"{'Peer 2 Key Generation':<25} {avg_peer2_keygen:<20.3f} {min(peer2_keygen_times) * 1000:<15.3f} {max(peer2_keygen_times) * 1000:<15.3f}")
    print(
        f"{'Total Key Generation':<25} {avg_total_keygen:<20.3f} {min([p1 + p2 for p1, p2 in zip(peer1_keygen_times, peer2_keygen_times)]) * 1000:<15.3f} {max([p1 + p2 for p1, p2 in zip(peer1_keygen_times, peer2_keygen_times)]) * 1000:<15.3f}")
    print(
        f"{'Shared Secret Computation':<25} {avg_shared_secret:<20.3f} {min(shared_secret_times) * 1000:<15.3f} {max(shared_secret_times) * 1000:<15.3f}")

    total_exchange_time = avg_total_keygen + avg_shared_secret
    print(f"{'Complete Key Exchange':<25} {total_exchange_time:<20.3f}")

    print("\nSECURITY ANALYSIS")
    print("=" * 60)
    print("Diffie-Hellman 2048-bit Security:")
    print("  • Key size: 2048 bits")
    print("  • Security level: ~112-bit equivalent")
    print("  • Problem basis: Discrete logarithm in finite fields")
    print("  • Known attacks: Pohlig-Hellman, Baby-step Giant-step")
    print("  • Quantum resistance: Vulnerable to Shor's algorithm")

    print("\nPROTOCOL PROPERTIES")
    print("=" * 60)
    print("Advantages:")
    print("  • Perfect forward secrecy")
    print("  • No prior shared secret required")
    print("  • Mutual authentication possible with certificates")
    print("  • Established and well-tested protocol")

    print("\nVulnerabilities:")
    print("  • Man-in-the-middle attacks without authentication")
    print("  • No built-in identity verification")
    print("  • Vulnerable to quantum attacks")
    print("  • Small subgroup attacks if parameters not chosen carefully")

    print("\nPEER-TO-PEER IMPLEMENTATION NOTES")
    print("=" * 60)
    print("🔐 For secure P2P file sharing:")
    print("   • Implement certificate-based peer authentication")
    print("   • Use ephemeral keys for each session")
    print("   • Validate received public keys are in valid range")
    print("   • Consider ECDH for better performance")
    print("   • Implement proper session management")

    return {
        'avg_keygen_time': avg_total_keygen,
        'avg_shared_secret_time': avg_shared_secret,
        'total_exchange_time': total_exchange_time
    }


def simulate_p2p_network():
    print("\nPEER-TO-PEER NETWORK SIMULATION")
    print("=" * 60)

    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    num_peers = 5
    peers = {}

    print(f"Initializing {num_peers} peers in P2P network...")

    for i in range(num_peers):
        peer_id = f"Peer_{i + 1}"
        private_key, public_key = generate_dh_keypair(p, g)
        peers[peer_id] = {
            'private': private_key,
            'public': public_key,
            'connections': {}
        }
        print(f"{peer_id}: Public key = {hex(public_key)}")

    print(f"\nEstablishing shared secrets between all peer pairs...")

    peer_list = list(peers.keys())
    total_exchanges = 0
    total_time = 0

    for i in range(len(peer_list)):
        for j in range(i + 1, len(peer_list)):
            peer1_id = peer_list[i]
            peer2_id = peer_list[j]

            start_time = time.perf_counter()

            shared_secret1 = compute_shared_secret(
                peers[peer2_id]['public'],
                peers[peer1_id]['private'],
                p
            )

            shared_secret2 = compute_shared_secret(
                peers[peer1_id]['public'],
                peers[peer2_id]['private'],
                p
            )

            end_time = time.perf_counter()
            exchange_time = end_time - start_time
            total_time += exchange_time
            total_exchanges += 1

            peers[peer1_id]['connections'][peer2_id] = shared_secret1
            peers[peer2_id]['connections'][peer1_id] = shared_secret2

            verification = "SUCCESS" if shared_secret1 == shared_secret2 else "FAILED"
            print(f"{peer1_id} ↔ {peer2_id}: {verification} ({exchange_time * 1000:.3f} ms)")

    avg_exchange_time = (total_time / total_exchanges) * 1000

    print(f"\nNETWORK STATISTICS")
    print("-" * 40)
    print(f"Total peer pairs: {total_exchanges}")
    print(f"Total exchange time: {total_time * 1000:.3f} ms")
    print(f"Average exchange time: {avg_exchange_time:.3f} ms")
    print(f"Network establishment time: {total_time * 1000:.3f} ms")

    print(f"\nCONNECTION VERIFICATION")
    print("-" * 40)
    all_verified = True
    for peer1_id in peers:
        for peer2_id in peers[peer1_id]['connections']:
            shared1 = peers[peer1_id]['connections'][peer2_id]
            shared2 = peers[peer2_id]['connections'][peer1_id]
            if shared1 != shared2:
                print(f"ERROR: {peer1_id} ↔ {peer2_id} shared secrets don't match!")
                all_verified = False

    if all_verified:
        print("✓ All peer connections verified successfully")

    return avg_exchange_time


if __name__ == "__main__":
    results = diffie_hellman_exchange()

    p2p_avg_time = simulate_p2p_network()

    print(f"\nFINAL RECOMMENDATIONS")
    print("=" * 60)
    print(f"📊 Performance Summary:")
    print(f"   • Single key exchange: {results['total_exchange_time']:.1f} ms")
    print(f"   • P2P network average: {p2p_avg_time:.1f} ms")
    print(f"   • Suitable for real-time P2P applications")

    print(f"\n🔒 Security Recommendations:")
    print("   • Implement peer authentication certificates")
    print("   • Use ephemeral keys for each file transfer session")
    print("   • Consider upgrading to ECDH for better performance")
    print("   • Implement perfect forward secrecy protocols")
    print("   • Add protection against man-in-the-middle attacks")