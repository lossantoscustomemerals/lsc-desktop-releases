# Firma degli aggiornamenti Windows

Questi file appartengono al repository pubblico ufficiale `lossantoscustomemerals/lsc-desktop-releases`. Il workflow firma una bozza già compilata, senza leggere il codice privato del gestionale. `windows-update-config.json` contiene soltanto le chiavi pubbliche.

Il segreto repository `LSC_UPDATE_SIGNING_KEY_PKCS8` contiene la privata Ed25519 in **DER PKCS8 codificato base64**, senza spazi: non è un PEM. Lo script non lo stampa né lo salva su disco. Per i rilasci successivi basta il segreto GitHub già configurato; non occorre fornire ogni volta il file privato locale.

1. Da Actions → **Firma aggiornamento Windows**, avviare `check_key_only: true` e `publish: false`. Non occorrono altri input: verifica il segreto e mostra soltanto l'impronta della pubblica, senza leggere o modificare release.
2. Preparare una bozza stabile `vX.Y.Z`, con note e i due pacchetti `Los-Santos-Custom-Setup-X.Y.Z.exe` e `Los-Santos-Custom-Portable-X.Y.Z.exe`.
3. Avviare da `main` con `check_key_only: false`, versione senza `v`, SHA256 e dimensioni esatte dei binari, `publish: false`. Scarica e verifica tutti i byte; nessuna mutazione della bozza.
4. Ripetere con gli stessi valori e `publish: true`. Solo dopo avere verificato binari, firme e tutti i sei asset pubblica come stabile `latest`. Una versione già pubblicata o non successiva alla stabile corrente viene rifiutata.
5. Controllare il riepilogo del workflow. Rilegge i quattro feed pubblici dopo la pubblicazione. La ricevuta `windows-release-receipt.json` distingue pubblicazione e verifica pubblica: se quest'ultima resta incompleta, non tentare di ripubblicare lo stesso numero.

I nuovi feed sono `latest-v2.json` e `portable-latest-v2.json`. I due originali mantengono **byte per byte i manifest firmati 2.0.1**, verificati con la pubblica precedente: i client non ancora migrati continuano a trovare un feed valido. Ogni release contiene due eseguibili e quattro manifest.

Permessi: `GITHUB_TOKEN` automatico con `contents: write` nel solo repository release. Esecuzione esclusivamente manuale su `main`, nessun trigger da pull request o fork; checkout e setup-node sono fissati a commit ufficiali. La configurazione iniziale del segreto richiede **Secrets: write**, chiave pubblica del repository e valore cifrato con LibSodium `crypto_box_seal`; l'API non restituisce la privata in chiaro. [Documentazione GitHub](https://docs.github.com/en/rest/actions/secrets#create-or-update-a-repository-secret).

Verifica locale: `node --test scripts/sign-windows-release.test.mjs`. I dieci test usano chiavi effimere e HTTP simulato, senza segreti o release reali.
