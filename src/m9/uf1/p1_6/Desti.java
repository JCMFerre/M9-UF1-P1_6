package m9.uf1.p1_6;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;

public class Desti {

    private KeyStore keyStore;
    private PrivateKey privateKey;
    private X509Certificate certificatOrigen;

    public Desti(String ksFile, String ksPwd) throws Exception {
        loadKeyStore(ksFile, ksPwd);
        loadPrivateKey("desti", ksPwd);
        loadCertificatOrigen("origencert");
    }

    /**
     * Carreguem el magatzem de claus.
     *
     * @param ksFile Fitxer a carregar al magatzem de claus.
     * @param ksPwd password per desbloquejar el magatzem.
     * @throws Exception
     */
    private void loadKeyStore(String ksFile, String ksPwd) throws Exception {
        keyStore = KeyStore.getInstance("JCEKS"); // JCEKS ó JKS
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            keyStore.load(in, ksPwd.toCharArray());
        }
    }

    /**
     * Carreguem la clau privada.
     *
     * @param alias Alias.
     * @param ksPwd La password per recuperar la clau.
     * @throws Exception
     */
    private void loadPrivateKey(String alias, String ksPwd) throws Exception {
        privateKey = (PrivateKey) keyStore.getKey(alias, ksPwd.toCharArray());
    }

    /**
     * Carreguem el certificat del Destí.
     *
     * @param alias Alias.
     * @throws Exception
     */
    private void loadCertificatOrigen(String alias) throws Exception {
        certificatOrigen = (X509Certificate) keyStore.getCertificate(alias);
    }

    /**
     * Verifiquem la informació.
     *
     * @param informacio Informació en byte[].
     * @param signaturaEnBytes Signatura en byte[].
     * @return true si s'ha verificat correctament, false el contrari.
     */
    public boolean verificar(byte[] informacio, byte[] signaturaEnBytes) {
        boolean esCorrecte = false;
        try {
            Signature signatura = Signature.getInstance("SHA256withRSA");
            signatura.initVerify(certificatOrigen.getPublicKey());
            signatura.update(informacio);
            esCorrecte = signatura.verify(signaturaEnBytes);
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException ex) {
            System.err.println(ex.getMessage());
        }
        return esCorrecte;
    }

    /**
     * Desxifrem la informació.
     *
     * @param missatgeXifrat Informació a desxifrar.
     * @return Missatge desxifrat en byte[].
     */
    public byte[] desxifraDadesReceptor(byte[] missatgeXifrat) {
        byte[] missatgeDesxifrat = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            missatgeDesxifrat = cipher.doFinal(missatgeXifrat);
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
        return missatgeDesxifrat;
    }

}
