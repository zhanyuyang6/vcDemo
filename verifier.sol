// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1d69af4934021e68d439efe29314ba72ccc15664597e2968390f453310ca6137), uint256(0x0178078054e4b4941812195717007d11592b1a8ce214528446a9f6740619a438));
        vk.beta = Pairing.G2Point([uint256(0x24c925deef7d0f03e3ce79bc22c3efcd050a19160541042fc112f1b649544ae7), uint256(0x298eb55b05ac618466f5ad86a310d2dec13fea2e2872e068091b33f010df7551)], [uint256(0x26b651d587df719ef7935a4373bf37b5c4c5f84a6888b981a3667b9ab850f4d3), uint256(0x047f82fbd8e8d615e41407da072b3ee12f837fac8458f3f3e4eea549f273bf4b)]);
        vk.gamma = Pairing.G2Point([uint256(0x209cf61a7a315a29f481ee6dce053c0d07dbcb500fbeebf43e97f6c1ddb72e80), uint256(0x1b2a13145f2a52c338f3f8feada29a5120294eafd87637da49074bf3843f0c27)], [uint256(0x1fce3ea4faa2f2e04a7135848fa4604157b164226a9f1734a72e37081d21764b), uint256(0x271e4870e30baf802bb454ef82842367b1c5e02c119706674cf081861cedf7d1)]);
        vk.delta = Pairing.G2Point([uint256(0x09c420d348837650fba1a3c118db7101af85f61edae54b9c791ec1e8e9e0b4d3), uint256(0x0535017d2ced8a8e22f49c6abc4acf62b28533f9474dad20329c5dbb4a87a3f4)], [uint256(0x296095ba5db6e8ef9bcf41ff14ce9df1b5ed2eb493ab19bb66c68c9c28937e18), uint256(0x2aa64f2aac8023cf6d1c28f53c0ddd03873ea2d83ed4674f6eb3b44281ebb802)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x189876d6ce489ef0513325fdaa6a049b77a787a437e0628f0185f1ae0319f7f6), uint256(0x2baffcab4fbffdc14d3f623858727bed34a8dc4394fc114b4b0dc2b750f3a5e2));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0c365e359530ec8b71a141f735742a90efe765b93eff904ad06b8585b67e2a34), uint256(0x1ef8a7512640d5dc3ae0f462faaa565d5cb5d01d9123184ce7519b0ef63658f6));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0468edaebb22e63a81bea6dd3c1dad2a8c78b8408d3042065cee494c2c634cc7), uint256(0x06f27685ef1cf1a32c9cb2cc0fcc0ac789e2beb34880d77407971adb99ef961b));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0c41b09b0fbc764e13629584b08bd91e27ae61f3d2ca6d4582989d77c8e8a8d9), uint256(0x19bfb23f1b3c134c45d3f9ae5d43d81f1a84f5f91d83000aecd00abdf64c429a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0cc528245e038bc0679682d401e99fba9c79003f5eb98ee6f6764ff7c491d8c5), uint256(0x27a6a57dc23ac1ab45d8b92b7cf99c489e18330fcd8c5099afdee3ce3ae81467));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2e4ab0fec4bc8eac19a17c53805e7ee953529f29704a3f9cd60d85c3a63f1c26), uint256(0x1b0963628d8e890cea697417c86d0598f88af7fa6df07274b50c7e58aa8c471d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1ecb74bd2705aa71d4d9a5b46f18093ccf3c8971ee0ef6a55d79519c6ff61f12), uint256(0x26f9c20fdbeebb4387093474938ab52d3834760e20137b40edafa70d4c4ad144));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x140d72997ec9938e7a9b94e4e0538e1c1abec292c36df5b1d7005e3fc050ebf3), uint256(0x1a4bc226b72dd21a5090010334c9f47b842fdfbce96e5b7e273327c1c1943380));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2f0fe71de875231bd933429d5dd89d9c80a2bc9e1a788ae8da9fe362fa95632d), uint256(0x0f7538046513ffecb2ec9cbe3bdeb69b134d81fc86cf8d4ce1bbee65c78c0ea9));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[8] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](8);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
