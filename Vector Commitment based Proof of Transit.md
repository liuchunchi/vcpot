---
stand_alone: true
category: std
submissionType: IETF
ipr: trust200902
lang: en

title: Vector Commitment-based Proof of Transit
abbrev: vcpot
docname: draft-liu-vc-proof-of-transit-00
obsoletes: 
updates:
date: 

area: 
workgroup: 

kw:
  - Proof of Transit
  - Inclusion Proof

author:
 -
  ins: C. Liu
  name: Chunchi Liu
  organization: Huawei
  email: liuchunchi@huawei.com
  street: 101 Ruanjian Ave
  city: Nanjing
  code: 210012
  country: China
 -
  ins: Q. Wu
  name: Qin Wu
  organization: Huawei
  country: China
  email: bill.wu@huawei.com


normative:
  RFC8205:
  RFC6810:

informative:
  RFC9217: 
  RFC7908:
  RFC9473:
  I-D.ietf-sfc-proof-of-transit-08: CISCOPOT
  I-D.dekater-panrg-scion-overview-04: SCION
  I-D.liu-path-validation-problem-statement: PVPS 
  I-D.irtf-cfrg-pairing-friendly-curves:
  RIvsFI:
    title: Opinion":" Is secured routing a market failure?
    date: 2022-12
    target: https://blog.apnic.net/2022/12/16/opinion-is-secured-routing-a-market-failure/
  KZG:
    title: Constant-Size Commitments to Polynomials and Their Applications
    target: https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf
  GOKZG:
    title: Go implementation of KZG proofs
    target: https://github.com/protolambda/go-kzg
  RUSTKZG:
    title: RUST implementation of KZG proofs
    target: https://github.com/ralexstokes/kzg
  PFC:
    title: PAIRING-FRIENDLY CURVES, Aurore Guillevic
    target: https://members.loria.fr/AGuillevic/pairing-friendly-curves/

--- abstract

This document describes an ordered Proof of Transit mechanism. 


--- middle

# Introduction {#intro}

Proof of Transit (POT) is a secure log or evidence that proves traffic transited certain elements of a network path, in a specified order. 

POT mechanism can prove the forwarding of a packet follows a specific path, in order to satisfy certain compliance or performance requirements. As a result, POT is important for several technologies that explicitly appoints traffic path, such as Service Function Chaining (SFC), Segment Routing (SR), Traffic Engineering (TE), etc-- it can help prove the compliance of a path, or at least, confirm deviation. Other use cases are discussed in {{-PVPS}}.

POT is a critical building block for routing security assurance, but a secure yet efficient POT mechanism is still under standardization. {{-CISCOPOT}} presented a Shamir Secret Sharing-based POT solution.

This document provides a secure, efficient ordered Proof of Transit mechanism using a cryptographic primitive named Vector Commitment. We select efficient cryptographic constructions of Vector Commitment, which is KZG polynomial commitment, for high computation efficiency and succinct proof size. We also define the efficiency benchmark and security definitions of Proof of Transit mechanisms. Since we believe order-compliance is a must, we omit "ordered" from now. 





<!-- is a mechanism that securely proves traffic transited a defined path hop-by-hop in a specific order. Each hop or node should create a crytographically unforgeable transit proof when processing this packet, sebsequently appending to the packet or send it to an out-of-band centralized controller, depending on who is to verify the proof. The proof itself should truthfully reflect the authentic processer identity and his position in this path. This proof should be verifiably tamper-proof and unforgeable.  -->


<!-- The exact value to each different protocol differs depending on the specific use case scenario. But in general, it benefits most to the protocols where a centralized party explictly appoints a path, such as source routing, segment routing, policy-based routing, traffic engineering, service function chaining, just to name a few. Their benefit to apply POT is obvious, since the value of these protocols rely on the sequenced forwarding or processing. However this does not mean it cannot contribute to protocols that operates across domains like BGP. BGP has its own implicit path implied by the routing tables updated by secure route announcement mechanisms like RPKI and BGPSEC. These mechanisms are designed aiming to assure that traffic can be forward from and to correct ASes, but since the final data plane verification method is missing, the security would only be implied, which leads to the gap between "routing integrity" and "forwarding integrity". POT, when implemented properly, can contribute to BGP and Internet security well too. 

Depending on the specific use case scenario, the instance of "path" and "node" is different. For example, in SFC context, the nodes are the service functions listed in the NSH header; in SRv6 context, the nodes are the segments listed on the segment list; in BGP context, the nodes are the ASes. But our proposed solution is focused on the SFC use case. The first proof of transit solution was proposed in {{-CISCOPOT}}, but it went discontinued due to negative SECDIR last call reviews. His work also focused on the SFC scenario. 

In this document, we use a cryptographic primitive named vector commitment to construct an ordered proof of transit mechansim. Since we believe order-compliance is a must, we omit "ordered" from now.  -->


# Terminology {#term}

The terminology and definition of key concepts in this document, such as path, node and link was defined in {{RFC9473}}.

- POT: Proof of Transit
- VC: Vector Commitment
- KZG: Kate, Zaverucha and Goldberg Polynomial Commitment
- SFC: Service Function Chaining
- SR: Segment Routing

# Background {#back}

The absence of a secure POT mechanism (along with lack of control to Internet devices) causes a gap between routing integrity and forwarding integrity. Routing information could be correctly propagated (with efforts like BGPSEC), but it is each router who makes the actual forwarding decisions, which can be affected by many faulty or malicious factors {{RIvsFI}}. POT mechanisms, if designed secure and efficient enough, can be a trustworthy mark or evidence reflecting the actual path a packet has taken. 


# Basic Idea {#basics}

The proposed method uses Vector Commitment (VC). A cryptographic commitment scheme allows Alice to commit to a secret value and reveal it later, while a Vector Commitment allows Alice to commit to a vector of secrets, and reveal it one-by-one or all at once. 

Simply put, VC allows Alice to commit a value into a specific position inside of an one-dimensional set, resembling the orchestration process of a routing path. It also allows a network element to compute an opening/inclusion proof for himself, proving who he is, what path he is on, what position he is on this path at the same time, attach to the packet and works as a transit proof. Only when the three-tuple matches with Alice's commit will the transit proof pass verification. 

Vector Commitment has many low level constructions-- Merkle Tree is certainly one of many possible constructions. But the advantage of this method is that we uses a much more efficient low-level construction that is KZG Polynomial Commitment, which allows stateless O(1) constant size of each inclusion proof (as compared with O(logN) in Merkle Trees), O(1) constant verification time of inclusion proof (as compared with O(logN) in Merkle Trees). N here is the total number of committed elements in a vector. Such efficiency advantage is critical when assessing the usability to apply advanced crypto to the routing area. Detailed comparisons will be given later.



(Diagram???)



# Solution {#sol}

## Algorithm {#algo}

We avoid cryptographic deep-dive. Consider VC as a blackbox with the following functions:

* Setup: On input a security parameter k, generate a set of puclic parameters pp for following functions.
* Commit: On input parameter pp, a vector V=(v_1, v_2, ..., v_N), output a commitment value C to the vector V. 
* Open: On input parameter pp, position i and auxiliary information, output an opening proof p_i.
* Verify: On input parameter pp, commitment C, opening proof p_i, output either pass or fail. 

This abstraction is given in https://www.di.ens.fr/~nitulesc/files/vc-sok.pdf

In KZG's actual construction, there is another step of conversion from vector V to a polynomial phi(x) which we will explain in the Approach section later. It also allows the opening of the whole polynomial and verification of the polynomial, which is not important and not common in other constructions, so it can be omitted. For details, please refer to the original paper {{-KZG}, Section 3.2 Construction: PolyCommit_DL for extended reading.


## Approach

In our approach, there is one network controller (Alice) and many network elements. We use controller and elements from now on. 

### Setup

- Controller chooses a pairing-friendly curve to use. She uses a unique ciphersuite identifier to represent the selection. Reference ciphersuite format is defined in Section 7.1 [@I-D.irtf-cfrg-bbs-signatures].
- Controller chooses maximum number of element t in the vector. Here t equals to maximum number of elements N on the path. 
- Controller chooses a random positive integer secret a. 
- Controller computes a t+1 tuple public parameter pp=(g, g^a, g^a+1, ..., g^a^t), where g is the group generator of the selected curve, part of public parameter of the curve. 

### Commit to a Path

- Controller decides a routing path, where each network element at position i's identity is defined as v_i in V. v_i can be a unique identifier (of any kind) of the element or a self-defined profile, as long as being public and verifiable. There is no size limit to the unique identifier, use a hash function (SHA256) to create a digest.
- Controller computes a polynomial phi(x) through Lagrange Interpolation, where the points are (1, v_1), (2, v_2), ..., (N, v_N). 1 to N are integers. The polynomial phi(x) is represented by N coefficients of it. 
- Given polynomial phi(x) and public parameters pp, controller computes a commitment C using the Commit() from KZG mechanism. 

### Configure

- Controller sends the following data to each network element: ciphersuite, public parameter pp, polynomial phi(x), commitment C for each element. 
- Controller also sends them for outside verifiers who wishes to conduct transit proof verification, for example, a security operation center or audit authority. Note transit proof is publicly verifiable.  

### Create Transit Proof

- Upon receiving a request to compute a transit proof, the network element compute an opening proof p_i using Open(), using the position i, his identity v_i and public parameter pp. 
- The transit proof p_i can be attached to the packet header, or sent out-of-band. 
- If the proof p_i is attached to the header, element of the next hop can verify it. Proof p is also aggregatable, meaning p_i and p_j can be aggregated into p_ij with the same size. 


### Verify Transit Proof

- The verifier takes public parameter pp, commitment C, index i, element's identity v_i, opening proof p_i, uses Verify() to accept or reject a transit proof. 

## Illustrative Example

TODO? 

# Sizing the Data for VCPOT

The transit proof is to be added in every packet, or sent out-of-band. 

The data size for VCPOT is relavent to the size of group G, which is relavent to different pairing-friendly curves we use. 

<!-- Curve       Public Parameters     Commitment       Transit Proof    Has Implementation Yet
BLS12-381       (N+1)*48     48    48       Y
BLS48       (N+1)*36     36    36       N
BW19-P286       (N+1)*36     36    36       N -->


|   Curve   |    Public Parameters |  Commitment |    Transit Proof | Has Implementation |
|-----------|----------------------|-------------|------------------|--------------------|
| BLS12-381 |    (N+1)*48          |          48 |               48 |    Y               |
| BLS48     |    (N+1)*36          |          36 |               36 |    N               |
| BW19-P286 |    (N+1)*36          |          36 |               36 |    N               |

where N is the maximum number of elements on the path. Assuming the curve parameters already exists in each element. 

# Living Implementation

https://github.com/liuchunchi/vcpot-demo

# Curves

KZG polynomial commitment utilizes pairing-friendly curves. Common implementations {{-GOKZG}}{{-RUSTKZG}} uses BLS12-381 elliptic curves defined in Section 4.2.1 of [@I-D.irtf-cfrg-pairing-friendly-curves]. With a field modulus q of 381 bits in length, we receive 126-bits of security (close enough to 128 bits). To achieve same bits of security, BN-curves requires 462 bits and increases spacial overhead. 

The reason why size of field modulus is important is because it is the exact size of a group element in G1, therefore both the size of a commitment and opening proof to be attached to the packet header and transmitted. Although BLS12-381 is the most popular curve, there are also curves with a smaller 286-bit G1-- BW19-P286 and BLS48. They adds 48B and 36B of additional overhead to the packet header, respectively. 


<!-- # Security and Efficiency of a POT Mechanism

## Security

We say a Proof-of-Transit mechanism is secure if the transit proof is correct, unforgeable, identity-binding and position-binding.

* **Correctness:** A transit proof created by the right node n_i at the position i must pass the verification. (probability of a correct proof not passing verification is smaller than a negligible function)

* **Unforgeability:** A transit proof forged by an outside malicious attack passing verification is smaller than a negligible function

* **Identity-binding:** A transit proof computed by a false node n_z at position i cannot pass a verification check.

* **Position-binding** A transit proof computed by a correct node n_i in the wrong position j, where i != j, cannot pass a verification check.

* **Hiding** * A transit proof may or may not directly reveal the creator's identity and/or his position. 


## Efficiency

The efficiency of a POT mechanism is evaluated by the efficiency of computing a transit proof, verifying a transit proof and the size of a transit proof. 

### Computation Efficiency

### Communication Efficiency

Size of a transit proof to be added to the packet. -->

# Benchmark and Comparison

The efficiency of a POT mechanism is evaluated by the efficiency of computing a transit proof, verifying a transit proof and the size of a transit proof. 


# Security Considerations

## No-mods, No-sweat

The POT approach described in this document did not make modifications to the KZG polynomial commitment itself-- we are merely using it. Therefore, the approach does not introduce additional potential security vulnerabilities compared to the original scheme. 

## No Post-Quantum Resistance

The approach described in this document uses bilinear pairing, which assumes (Elliptic Curve) Discrete Log Problem is hard. This also means this approach is not quantum-resistant. We have two arguments for that:

1. If PQ-safe is a must, lattice-based or hash-based VC construction is also available (https://www.di.ens.fr/~nitulesc/files/vc-sok.pdf). For instance, Fast Reed-Solomon Interactive Oracle Proof (FRI) is another alternative vector commitment construction to KZG. FRI commitment is constructed using merkle trees and is hence quantum resistant, but the proof size is bigger, slower to verify, dependent to the number of elements in the vector (both O(log\^2N)). 

2. Considering general elliptic curve cryptography is still in wide use, it is fair to say forging a transit proof is less severe than forging an ECDSA signature to Bitcoin.

## Need Trusted Setup (A Centralized Controller)

Construction to Proof-of-Transit mechanisms are not unique. For our method, we require a centralized trusted setup to generate and distribute the parameters. But this is not very problematic since a network controller that orchestrates a path can (and should) also serve as a setup center. Nevertheless, controller-side implementation is needed for Step 1 Configure. 

## Router Participating or Not

Tracking the actual path that a traffic packet took is hard. In a stateless hop-by-hop scenario, either add an evidence
















## Cryptographic Commitment

A cryptographic commitment scheme works like an envelope in the Oscar award presenting ceremony. Typically consists of 3 stages:

1. Alice commit to a value v by computing a commitment value c. 
2. She publicize the commitment c, declaring that she has chosen a value, but this value is kept secret for now.
3. After publicizing the commitment, Alice can reveal the original value v and Bob can verify if the later revealed value is indeed the value Alice commited at the very beginning. 
  
Note that the commitment value c itself is both hiding and binding, meaning the adversary cannot interpret the exact value just by looking at the commitment in stage 2, nor can Alice change the original value that also links to this commitment after stage 1. Analogous to Oscar, the value v is the winner name, the commitment c is the white envelope, Alice is the Academy and announcer, and Bob is the audience. 

## Vector Commitment 

Vector commitment is an extenstion to the commitment scheme by replacing a single value with a vector of values, each binds to its index in the vector. In vector commitment, Alice would also compute a commitment that links to a vector. But in the revealing stage, Alice can reveal one or many values in the vector at a time by computing an opening proof. Aside of the binding and hiding properties, vector commitment also has a position-binding property, where Alice must reveal the value v_i with the correct index i, in order to compute a correct opening proof.  

Commitment scheme is a concept and has many different specific cryptographic constructions. It is natural to think hash functions can do the job. Yes it can, but the difference lies in the computational complexity. Hash alone can build a commitment scheme and merkle tree can build vector commitment, but everytime Bob verifies the opening proof, he will need O(n) and O(logn) time to recalculate, same as the time that Alice computes the opening proof. Also Bob would need O(n) and O(logn) amount of auxiliary information to verify. 

In this document we utilize an efficient construction named Kate-Zaverucha-Goldberg (KZG) polynomial commitment, which is widely used in Ethereum Layer-2 Scaling[]. The advantage of this construction is it only need Bob O(1) time to verify the opening proof, where n is the length of the vector. Also the size of the opening proof is also O(1). When mapping to the POT solution, the vector value v is the path selected by the controller, the commitment value c is the transit proof verification reference value, the opening proof if the transit proof, Alice is the controller and router, Bob is the external verifier. The advantage of KZG commitment is that the extra verification cost is O(1), and extra packet overhead carrying the transit proof is also O(1), regardless of the length of the path. Most importantly, the natual position-binding property of vector commitment scheme is the best fit for the "ordering" requirement for POT.  



# Modelling the Ideal Solution {#idealsolution}

## Required Functionality:

The path validation mechanism consists of the following algorithms:

1. Configure: Setup control plane parameters based on a security parameter.
    * Input: Security parameter
    * Output: Control plane parameter distributed

2. Commit: Generates a commitment proof for the chosen path using public parameters and the path itself.
    * Input: public parameters, path P
    * Output: Commitment Proof C of the path P

3. CreateTransitProof (in-situ / altogether): Generates transit proofs for individual nodes or sets of nodes, either during data processing or when transmission finishes.
    * Input: public parameters, index i of node n_i or indices I of a set of node n_I, identity information of node n_i or set of nodes n_I.
    * Output: Transit proof p_i or batch transit proof p_I

4. VerifyTransitProof (in-situ / altogether): Verifies transit proofs for individual nodes or sets of nodes, either in-step or all at once.
    * Input: public parameters, transit proof p_i/p_I, index i of node n_i or indices I of a set of node n_I, identity information of node n_i or set of nodes n_I.
    * Output: success = 1, fail = 0

The Network Operator performs the Configure and Commit steps. The CreateTransitProof step could be done by either each node n_i during he is processing the data, or the end node n_N when the transmission finishes altogether. That being said, the VerifyTransitProof step can also be executed in an in-situ (for step-by-step control and visibility) or one-time fashion. Usually the VerifyTransitProof step is executed by the observer, but it can also be executed by the next-hop node for origin verification.



# Source Routing vs Conventional Routing {#major}

The two biggest use case scenarios would be source routing and conventional routing, where the former has a centralized party that selects and appoints an explicit path, and the latter only forwards packets in a best-effort and decentralized way.  

Source routing would compute a reference value as the commitment to the path. The transit proof can be verified against the reference value, therefore does not need to be readable. Conventional routing does not have a selection step of path, so proof of transit does not need to be verified against some reference value, only need to be readable. Note that the transit proof is encryted and is decryptable by destination is also considered readable, just not plaintext readable. 





In certain scenarios, the source host wish to have explicit control over the path that network traffic takes, in order to meet certain performance, security or regulatory compliance requirements. This requirement cultivates some specific explicit routing (or say path-aware networking) techniques including source routing, policy-based routing (PBR), traffic engineering and segment routing, etc. Path validation is a critical verification technique that checks whether the planned path was strictly followed, and a secure solution calls for high accuracy and unforgeability. However, this goal is hard to achieve due to several reasons:

* Data is intangible by nature. It is hard to track secret data theft (malicious redirection or keeping a copy) once it is fully controlled by a router. 
* The proof-of-transit requires self-reporting and it is hard to verify whether the router lied or not. 




In the current Internet architecture, the network layer provides best-effort service to the endpoints using it {{RFC9217}}. This means that the endpoints are unaware, unable to visualize, and unable to control the network path between them, and thus the traffic inside the path too. This deficiency not only undermines Internet routing security but also hampers the development of new concepts like path-aware networking {{RFC9217}}{{PAIA}}. Exploiting this vulnerability, various routing attacks have emerged, including--

* Routing Hijack / Prefix Hijack: AS (Autonomous System) incorrectly announces prefix ownership, diverting normal traffic to the wrong AS.
* Route Injection / Traffic Detour: Attacker injects additional hops into a path, redirecting traffic to locations where it can be monitored, analyzed, or even manipulated before being sent back to the original destination.
* Route leak: Propagation of routing announcements beyond their intended scope {{RFC7908}}, causing unintended ASes to receive traffic.
* Denial of Service (DOS): Adversary overwhelms important routers with interfering traffic, preventing them from receiving and processing valid traffic.

These attacks exploit the trusting and flexible nature of the Internet, resulting in unreliability in both path establishment and actual data forwarding. To address this issue, several works are proposed focusing on securing network path in the control plane. Resource Public Key Infrastructure (RPKI) {{RFC6810}} consider IP prefixes as resources, and their ownership must be proven by signed statements called Route Origin Authorizations (ROAs), issued by the root CA or authorized CAs of the Internet Routing Registry -- similar to how certificates work in regular PKI. Through a chain of ROAs, BGPSec {{RFC8205}} can secure an AS path.

While these measures provide necessary authentication services and enhance routing security in the control plane, they have limitations. Securing a path in the control plane does not necessarily mean we can control and track the actual forwarding of traffic within these paths. To put it simply, even though we have secured highways to connect correct locations so that cars can reach their intended destinations, controlling how cars actually travel on the highways and reliably logging their movements is a separate challenge. In order to achieve this goal, an effective path validation mechanism should enable data packets to carry both mandatory routing directives and cryptographically secure transit proofs in their headers. This mechanism should serve as an orthogonal complement to existing techniques that primarily focus on the control plane. Cisco made an exploratory attempt by designing a Proof of Transit scheme using modified Shamir Secret Sharing {{-CISCOPOT}}. Although they did not provide a rigorous security proof and the work regretfully discontinued but the question they asked is too significant to be left undiscussed.



# Use Cases {#usecases}

We have compiled a list of use cases that highlight the importance of path validation. We invite discussions to add more cases, aiming to cover as many scenarios as possible.

## Use Case 1: Proof of Service Level Assurance

Internet Service Providers (ISPs) often have different levels of routing nodes with varying service qualities. When customers like Alice subscribe to premium plans with higher prices, it is reasonable for them to expect superior connection quality, including higher bandwidth and lower latency. Therefore, it would be beneficial to have a mechanism that ensures Alice's traffic exclusively traverses premium routing nodes. Additionally, it is important to provide Alice with verifiable proof that such premium services are indeed being delivered.

## Use Case 2: Proof of Security Service Processing

Service Function Chaining enables the abstraction of services such as firewall filtering and intrusion prevention systems. Enterprises need to demonstrate to others or verify internally that their outbound and inbound traffic has passed through trusted security service functions. In this context, the service function acts as the node that must be transited. After the processing and endorsing of these security service functions, traffic becomes verifiably more reliable and more traceable, making it possible to reduce spamming and mitigate Distributed Denial-of-Service (DDoS) attacks.

## Use Case 3: Security-sensitive Communication

Routing security is a critical concern not only on the Internet but also within private networks. End-to-end encryption alone may not be sufficient since bad cryptographic implementations could lead to statistical information leak, and bad cryptographic implementation or API misuse is not uncommon {{BADCRYPTOIMPL1}}{{BADCRYPTOIMPL2}}. If a flow of traffic is maliciously detoured to the opposing AS and secretly stored for cryptanalysis, useful information (such as pattern of plaintexts) could be extracted by the adversary. Thus, when given a specific path or connection, it is crucial to ensure that data packets have solely traveled along that designated route without exceeding any limits. Ultimately, it would be advantageous to provide customers with verifiable evidence of this fact.


# Design Goals {#designgoals}

As the name suggests, the Network Path Validation mechanism aims to achieve two main goals:

1. Enforcement: Committing to a given network path and enforcing traffic to traverse the designated nodes in the specified order.
2. Validation: Verify the traffic indeed transited the designated nodes in exact order specified for this path.

The enforcement and validation to the traffic forwarding are two sides of a coin. In order to achieve these goals, two additional pieces of information must be added to the data header.

1. Routing Directive: A routing directive commands the exact forwarding of the data packet hop-by-hop, disobeying which will cause failure and/or undeniable misconduct records.
2. Transit Proof: A transit proof is a cryptographic proof that securely logs the exact nodes transited by this data packet.


# Modelling the Ideal Solution {#idealsolution}

## Roles:

The path validation mechanism should include three roles:

* The network operator chooses or be given a routing path P and commit to it. P = (n_1, n_2, …, n_i, …, n_N) is an ordered vector consists of N nodes. The network operator also does the setup and pre-distribution of the public parameters.
* The forwarding “node” is a physical network device or a virtual service that processes and forwards the data traffic. Within that path, this node is the minimal atomic transit unit meaning there are no other perceptible inferior nodes between these regular nodes.
* The observer is an abstract role that represents public knowledge. Any publicized information is known to the observer. Any person or device who is interested in examining the trustworthiness of this routing path could be an instance of observer. An observer can verify publicized information such as node identity or transit proof with an unbiased property.


## Required Functionality:

The path validation mechanism consists of the following algorithms:

1. Configure: Setup control plane parameters based on a security parameter.
    * Input: Security parameter
    * Output: Control plane parameter distributed

2. Commit: Generates a commitment proof for the chosen path using public parameters and the path itself.
    * Input: public parameters, path P
    * Output: Commitment Proof C of the path P

3. CreateTransitProof (in-situ / altogether): Generates transit proofs for individual nodes or sets of nodes, either during data processing or when transmission finishes.
    * Input: public parameters, index i of node n_i or indices I of a set of node n_I, identity information of node n_i or set of nodes n_I.
    * Output: Transit proof p_i or batch transit proof p_I

4. VerifyTransitProof (in-situ / altogether): Verifies transit proofs for individual nodes or sets of nodes, either in-step or all at once.
    * Input: public parameters, transit proof p_i/p_I, index i of node n_i or indices I of a set of node n_I, identity information of node n_i or set of nodes n_I.
    * Output: success = 1, fail = 0

The Network Operator performs the Configure and Commit steps. The CreateTransitProof step could be done by either each node n_i during he is processing the data, or the end node n_N when the transmission finishes altogether. That being said, the VerifyTransitProof step can also be executed in an in-situ (for step-by-step control and visibility) or one-time fashion. Usually the VerifyTransitProof step is executed by the observer, but it can also be executed by the next-hop node for origin verification.


# Security {#security}

As we can see, the creation and verification of the transit proof is the critical part of the mechanism. Therefore, we define the security of the Network Path Validation mechanism around the security of the transit proof:

We say a Network Path Validation mechanism is secure if the transit proof is correct, unforgeable and binding.

* **Correctness:**
Transit proof created by the right node n_i at the position i must pass the verification. (probability of a correct proof not passing verification is smaller than a negligible function)

* **Unforgeability:** Transit proof at position i must only be created by the node n_i. (probability of a forged proof passing verification is smaller than a negligible function)

* **Binding:** An identity value at position i different than what is committed created by polynomial adversary cannot pass a verification check.

Other security discussions like replay attack resistance are discussed separately. Since transit proof is added to the header, the compactness of proof, short proof creation and verification time is also critical. Ideally:

* **Efficiency:** The creation time, verification time and size of the transit proof is sublinear to the number of total nodes on a path.




# Out-of-scopes {#oos}

## Proof of non-transit 

Although a secure POT mechanism, by logic, should imply a proof of non-transit (PONT). But due to the inevitable existence of inferior level nodes and layered design of Internet, we can only focus on the perceivable nodes on the present level where the protocol we are extending is on. For example, nodes perceivable in SRv6 context should only be the segments explictly listed on the segment list; nodes perceivable in SFC context should only be the service functions listed in the NSH header. This complies to the layered design of the Internet and whether there exists a transparent channel between the peers is, and should be, out-of-scope. Whether or not the path is passing some prohibited physical location or lower level devices deserves a different work. After all, this is a proof of transit work, not proof of non-transit. 


# Generalized Algorithm Considerations 

Vector Commitment can be seen as a sub-type of Cryptographic Accumulators, which can prove the membership of one element in a set. What is special about VC is it can also prove the order or membership. In use cases where the order is not important, or cryptographic capability is limited, we can use simplified constructions of Cryptographic Accumulators, proving membership (transit) is ok. Simplified CA include: Merkle Tree. 

# IANA Considerations

This document has no IANA actions.



--- back


