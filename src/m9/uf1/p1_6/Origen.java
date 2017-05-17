package m9.uf1.p1_6;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;

public class Origen {

    private KeyStore keyStore;
    private PrivateKey privateKey;
    private X509Certificate certificatDesti;

    public Origen(String ksFile, String ksPwd) throws Exception {
        loadKeyStore(ksFile, ksPwd);
        loadPrivateKey("origen", ksPwd);
        loadCertificatDesti("desticert");
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
    private void loadCertificatDesti(String alias) throws Exception {
        certificatDesti = (X509Certificate) keyStore.getCertificate(alias);
    }

    /**
     * Xifrem el missatge.
     *
     * @param missatge Missatge a xifrar.
     * @return missatge xifrat en byte[].
     */
    public byte[] xifrar(String missatge) {
        byte[] missatgeEncriptat = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, certificatDesti.getPublicKey());
            missatgeEncriptat = cipher.doFinal(missatge.getBytes());
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
        return missatgeEncriptat;
    }

    /**
     * Signem la informació.
     *
     * @param informacio Informació a signar.
     * @return signatura en byte[].
     */
    public byte[] signar(byte[] informacio) {
        byte[] signatura = null;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(informacio);
            signatura = signature.sign();
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
        return signatura;
    }

}
