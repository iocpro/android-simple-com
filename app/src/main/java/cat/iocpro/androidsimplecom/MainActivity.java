package cat.iocpro.androidsimplecom;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.ProxyInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class MainActivity extends AppCompatActivity {
    String error = ""; // string field

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button buttonWithProxy = findViewById(R.id.buttonHttps);
        CheckBox proxyCB = findViewById(R.id.proxyCheckbox);
        CheckBox trustCB = findViewById(R.id.trustCaCheckbox);

        buttonWithProxy.setOnClickListener((View v) -> {
            ExecutorService executor = Executors.newSingleThreadExecutor();

            executor.execute(new Runnable() {
                @Override
                public void run() {
                    // Tasques en background (xarxa)
                    String data = getDataFromUrl("https://api.myip.com",
                            proxyCB.isChecked(), trustCB.isChecked());

                    Handler handler = new Handler(Looper.getMainLooper());
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            // Tasques a la interfície gràfica (GUI)
                            TextView tv = findViewById(R.id.textView);
                            tv.setText(data);

                            Toast.makeText(MainActivity.this,
                                    "IP actualitzada",Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            });
        });
    }


    private String getDataFromUrl(String urlStr, boolean proxified, boolean trustSysCAs) {

        String result = "SENSE PROXY: ";
        error = "";
        int resCode = 0;
        try {
            URL url = new URL(urlStr);
            System.setProperty("http.keepAlive", "false");
            HttpsURLConnection httpsConn = null;// (HttpsURLConnection) url.openConnection();

            // Proxy
            if( proxified ) {
                try {
                    ConnectivityManager connectivityManager = (ConnectivityManager) getApplicationContext().getSystemService(
                            Context.CONNECTIVITY_SERVICE);
                    Network activeNetwork = connectivityManager.getActiveNetwork();
                    ProxyInfo proxyInfo = connectivityManager.getDefaultProxy();

                    if (proxyInfo != null) {
                        // aconseguim els settings de Proxy del sistema operatiu
                        String proxyHost = proxyInfo.getHost();
                        int proxyPort = proxyInfo.getPort();
                        Log.v("HTTPS","Configurant proxy a "+proxyHost+" port="+proxyPort);
                        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
                        httpsConn = (HttpsURLConnection) url.openConnection(proxy);

                        // Confiar en una CA personalitzada
                        if( trustSysCAs ) {
                            // Carregar el certificat des de res/raw/mycert.crt
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            InputStream caInput = getApplicationContext().getResources().openRawResource(R.raw.zap_root_ca);
                            Certificate ca;
                            try {
                                ca = cf.generateCertificate(caInput);
                                Log.d("CA", "Certificat=" + ((X509Certificate) ca).getSubjectDN());
                            } finally {
                                caInput.close();
                            }

                            // Crear un KeyStore que conté el certificat CA
                            String keyStoreType = KeyStore.getDefaultType();
                            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                            keyStore.load(null, null);
                            keyStore.setCertificateEntry("ca", ca);

                            // Crear un TrustManager que confia en el CA del KeyStore
                            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
                            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
                            tmf.init(keyStore);

                            // Crear un SSLContext que utilitza el TrustManager
                            SSLContext sslContext = SSLContext.getInstance("TLS");
                            sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());

                            // Utilitzar SSLContext a la connexió proxificada
                            httpsConn.setSSLSocketFactory(sslContext.getSocketFactory());
                        }

                        result = "AMB PROXY: ";
                    } else {
                        Log.e("PROXY","No es pot aconseguir la informació de proxy del sistema.");
                        return "AMB PROXY: No es pot aconseguir la informació de proxy del sistema.";
                    }
                } catch (Exception e) {
                    Log.e("HTTPS","No s'ha pogut utilitzar el Proxy");
                    e.printStackTrace();
                    return "ERROR: no s'ha pogut utiltizar el Proxy. Configura primer el proxy a la connexió de xarxa i torna a provar.";
                }
            } else {
                httpsConn = (HttpsURLConnection) url.openConnection();
            }

            // Petició HTTPS
            httpsConn.setAllowUserInteraction(false);
            httpsConn.setInstanceFollowRedirects(true);
            httpsConn.setRequestMethod("GET");
            httpsConn.connect();
            resCode = httpsConn.getResponseCode();
            result += "("+resCode+") ";

            if (resCode == HttpURLConnection.HTTP_OK) {
                InputStream in;
                in = httpsConn.getInputStream();

                BufferedReader reader = new BufferedReader(new InputStreamReader(
                        in, "iso-8859-1"), 8);
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                in.close();
                result += sb.toString();
            } else {
                error += resCode;
            }
            if (httpsConn != null) {
                httpsConn.disconnect();
            }
        } catch (IOException e) {
            e.printStackTrace();
            result += e.toString();
        }
        return result;
    }


}