# BIP_Schnorr

path:bip-schnorr.mediawiki

## 优势

理论上相对于ECDSA

- **安全性**：更明确的安全性证明，基于random oracle假设

- **不可扩展性**：不存在ECDSA中不知道私钥也能通过*扩展方式*获得虚假签名的问题。
- **线性**：可以构造聚合签名

实现上：

**签名编码**：签名编码为固定64bytes，比DER-encoding的不固定且最高72bytes好

**验证批处理**：批处理验证速度快*O(n / log n)*

**可用**：使用secp256k1椭圆曲线跟Bitcoin一样，所以可以使用原始Bitcoin公私钥

------

## 应用

### MultiSig

reference : *Simple Schnorr Multi-Signatures with Applications to Bitcoin*

优势：

- 签名定长
- 安全*key aggregation*

#### 简单MultiSig方案

*私钥集{x1…xn}, 公钥集{X1…Xn}, Xi=g^x*

- 单独生成随机数ri, 计算并共享Ri=g^ri
- 计算R=Ri积，X=Xi积，c=Hash(X,R,m)
- 每个签名si = ri + c*xi，合成签名为s=si和 mod p，最终签名为（R,s）
- 可以使用传统schnorr验证方法验证，公钥为X。验证函数如下：
![image-20190425111704676](/Users/houjx/Library/Application Support/typora-user-images/image-20190425111704676.png)

**简单方案存在rogue-key attack问题**：

![image-20190425105207449](/Users/houjx/Library/Application Support/typora-user-images/image-20190425105207449.png)

使用能够抵消其他公钥的虚假公钥X1，虚假公钥X1和私钥x1是不匹配的。
需要先得知其他人的公钥才能生成虚假公钥。

**Micali-Ohta-Reyzin方案解决rogue-key attack**：

reference:*On the Risk of Disruption in Several Multiparty Signature Schemes*

修改部分为：

- ci = Hash(<L>,R,m), <L>为公钥集合的编码。
- si = ri + ci*xi
- 新验证函数![image-20190425111826822](/Users/houjx/Library/Application Support/typora-user-images/image-20190425111826822.png)

- 共享Ri前先共享Hash(Ri)，能够防止根据获取到的别人的Ri恶意修改自己的Ri。

存在问题：

- 需要知道全部的公钥集不能够*key aggregation*

- 交互式 

  1. 共享Hash(Ri)
  2. 共享Ri
  3. 共享si

#### Simple Schnorr MultiSig with Application to Bitcion方案
