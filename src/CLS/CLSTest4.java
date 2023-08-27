package CLS;

//import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
//import it.unisa.dia.gas.plaf.jpbc.pairing.AbstractPairing;

//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class CLSTest4 {
	private Pairing pairing;
//    private Element h;

	// 初始設定生成params
	public CLSTest4() {
		int rBits = 128;
		int qBits = 256;
		System.out.println("========== Initialize Elliptic Curve ==========");
		// 生成初始橢圓曲線，後續要用導入的，以避免不同
		TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
		PairingParameters parameters = pg.generate();
		this.pairing = PairingFactory.getPairing(parameters);

	}

	public SetupResult setup() {
		// S= masterKey
		Element P = pairing.getG1().newRandomElement().getImmutable();
		Element s = pairing.getZr().newRandomElement().getImmutable();
		Element P0 = P.duplicate().mulZn(s).getImmutable();
		System.out.println("========== Set params system parameters ==========");
		System.out.println("The system parameters are");
		System.out.println("params:P,P0,s");
		System.out.println("P : " + P);
		System.out.println("P0 : " + P0);
		System.out.println("s : " + s);

		return new SetupResult(pairing, P, P0, s);
	}

	public class SetupResult {
		public Pairing pairing;
		public Element P;
		public Element P0;
		public Element s;

		public SetupResult(Pairing pairing, Element P, Element P0, Element s) {
			this.pairing = pairing;
			this.P = P;
			this.P0 = P0;
			this.s = s;
		}
	}

	// 由msk生成ID對應的部分私鑰
	public Element partialPrivateKeyExtract(Element masterKey, String ID) {
		System.out.println("=========== ID generates the corresponding part of the private key ==========");
		byte[] idBytes = ID.getBytes(StandardCharsets.UTF_8);
		// System.out.println("idBytes:" + idBytes);

		Element QA = pairing.getG1().newElementFromHash(idBytes, 0, idBytes.length).getImmutable();
		// System.out.println("QA:" + QA);

		Element DA = QA.duplicate().mulZn(masterKey).getImmutable();
		// System.out.println("DA:" + DA);
		System.out.println("The generated partial private key is");
		System.out.println("DA : " + DA);

		return DA;
	}

	// 由用戶端生成的密鑰，和partialPrivateKeyExtract生成的DA，生成完整的私鑰
	public Element setPrivateKey(Element DA, Element xA) {
		System.out.println("========== Generate complete private key ==========");
		Element SA = DA.duplicate().mulZn(xA);
		System.out.println("The full private key is");
		System.out.println("SA : " + SA);

		return SA;
	}

	// 透過params和用戶端生成的密鑰，生成公鑰
	public Element[] setPublicKey(SetupResult params, Element xA) {
		System.out.println("========== Generate public key successfully ==========");
		Element[] publicKey = new Element[2];

		// publicKey[0] = XA
		publicKey[0] = params.P.mulZn(xA).getImmutable();
		// System.out.println("params.P:" + params.P);

		// publicKey[1] = YA
		publicKey[1] = params.P0.mulZn(xA).getImmutable();
		// System.out.println("params.P0:" + params.P0);
		System.out.println("public key is");
		System.out.println("publicKey : " + publicKey);

		return publicKey;
	}

	// 這邊進行簽章
	public Element[] sign(SetupResult params, byte[] M, String ID, Element SA) {
		System.out.println("========== Signature ==========");
		Element a = params.pairing.getZr().newRandomElement().getImmutable();
		// System.out.println("a:" + a);

		Element aP = params.P.duplicate().mulZn(a).getImmutable();
		Element P = params.P;

		Element r = pairing.pairing(aP, P).getImmutable();
		// System.out.println("r:" + r);

		Element elementM = pairing.getZr().newElementFromHash(M, 0, M.length).getImmutable();
		// System.out.println("elementM:" + elementM);

		Element v = r.duplicate().mulZn(elementM).getImmutable();
		;
		// System.out.println("v:" + v);

		Element U = SA.mulZn(v).add(aP);
		// System.out.println("U:" + U);

		Element[] sign = new Element[2];
		sign[0] = U;
		sign[1] = v;
		System.out.println("The signature result is");
		System.out.println("sign : " + sign);

		return sign;
	}

	// 驗證簽章的有效性
	public String Verify(Element[] sign, SetupResult params, byte[] M, Element[] publicKey, String ID) {
		String VerifyResult = "";
		Element XA = publicKey[0];
		Element P0 = params.P0;
		Element YA = publicKey[1];
		Element P = params.P;
		Element U = sign[0];
		Element v = sign[1];

		// 计算左侧等式 e(XA, P0)
		Element leftSide = pairing.pairing(XA, P0);

		// 计算右侧等式 e(YA, P)
		Element rightSide = pairing.pairing(YA, P);

		// 驗證公鑰的有效性，如果無效直接停止
		if (leftSide.isEqual(rightSide)) {
			System.out.println("Valid verification, enter signature verification");

			byte[] idBytes = ID.getBytes(StandardCharsets.UTF_8);
			// System.out.println("idBytes:" + idBytes);
			Element QA = pairing.getG1().newElementFromHash(idBytes, 0, idBytes.length).getImmutable();
			// System.out.println("QA"+QA);

			Element r = (pairing.pairing(YA.negate(), QA).powZn(v)).mul(pairing.pairing(U, P));
			// System.out.println("r =" + r);

			Element elementM = pairing.getZr().newElementFromHash(M, 0, M.length).getImmutable();
			// System.out.println("elementM"+elementM);

			Element V_Verify = r.duplicate().mulZn(elementM).getImmutable();
			// System.out.println("V_Verify" + V_Verify);

			if (v.equals(V_Verify)) {
				VerifyResult = "Valid signature";
			} else {
				VerifyResult = "Invalid signature";
			}

		} else {
			// System.out.println("無效驗證");
			VerifyResult = "Invalid signature";
			return VerifyResult;
			// 输出 ⊥ 表示验证失败，并中止验证过程
			// 可以选择抛出异常或采取其他操作
		}
		return VerifyResult;
	}

	// 用於將訊息轉為Bytes
	public byte[] msgToZn(String message) {
		return message.getBytes(StandardCharsets.UTF_8);
	}

	public static void main(String[] args) {

		CLSTest4 clpkc = new CLSTest4();
		SetupResult params = clpkc.setup();
		Pairing pairing = params.pairing;
		// System.out.println("pairing: " + pairing);
		Element P = params.P;
		// System.out.println("P: " + P);
		Element P0 = params.P0;
		// System.out.println("P0: " + P0);

		String ID = "user@email.com";
		Element masterKey = params.s;
		// System.out.println("masterKey: " + masterKey);

		// partialPrivateKey = DA, DA = params,masterKey,ID
		Element partialPrivateKey = clpkc.partialPrivateKeyExtract(masterKey, ID);
		// System.out.println("partialPrivateKey: " + partialPrivateKey);

		// secretValue = XA, 用戶自選一組數字(這邊用隨機生成)生成密鑰
		Element secretValue = pairing.getZr().newRandomElement().getImmutable();
		// System.out.println("secretValue: " + secretValue);

		// privateKey = SA ，SA = params,DA, XA
		Element privateKey = clpkc.setPrivateKey(partialPrivateKey, secretValue);
		// System.out.println("privateKey: " + privateKey);

		Element[] publicKey = clpkc.setPublicKey(params, secretValue);
		// System.out.println("publicKey: " + publicKey[0]+publicKey[1]);

		String msg = "hello world!!!!!";
		// System.out.println("msg: " + msg);

		byte[] encodemsg = clpkc.msgToZn(msg);
		// System.out.println("encodemsg: " + encodemsg);

		Element[] sign = clpkc.sign(params, encodemsg, ID, privateKey);
		System.out.println("The result of the signature is" + sign);
		System.out.println(sign[0]);
		System.out.println(sign[1]);

		String VerifyResult = clpkc.Verify(sign, params, encodemsg, publicKey, ID);
		System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");
		System.out.println("+   The result of verifying the signature is   +");
		System.out.println("+              " + VerifyResult + "                 +");
		System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");
	}
}
