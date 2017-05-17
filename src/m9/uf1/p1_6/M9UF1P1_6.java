package m9.uf1.p1_6;

import java.io.File;

public class M9UF1P1_6 {

    public static void main(String[] args) throws Exception {
        String password = "ferreria";

        // Instanciem les classes amb les rutes dels .jks i la password.
        String certOrigen = "SSL" + File.separator + "origen.jks";
        Origen origen = new Origen(certOrigen, password);
        String certDesti = "SSL" + File.separator + "desti.jks";
        Desti desti = new Desti(certDesti, password);

        // Encriptem la informació passant-li al origen.
        byte[] informacioXifrada = origen.xifrar("JEJEJE xifrat i signat.");

        // Signem la informació xifrada i ens guardem la signatura.
        byte[] signatura = origen.signar(informacioXifrada);

        // Verificant amb el destí, passant-li l'informació i la signatura.
        boolean infoVerificada = desti.verificar(informacioXifrada, signatura);

        // Comprovem la verificació.
        if (infoVerificada) {
            // Si la informació esta verificada correctament, desxifrem la informació
            // amb el destí.
            byte[] informacioDesxifrada = desti.desxifraDadesReceptor(informacioXifrada);
            // Creem un String amb els byte[] de la informació . 
            System.out.println(new String(informacioDesxifrada));
        } else {
            System.out.println("¡No a passat el test de verificar!");
        }
    }

}
