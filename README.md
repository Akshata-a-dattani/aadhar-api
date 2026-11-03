# Aadhaar verification integration starter

This Flask application is a **local flow demonstration**, not Aadhaar authentication. It replaces the original hard-coded Aadhaar/name lookup with a consent screen and a mock provider redirect. Use the fictional 12-digit value `000000000000` to see a simulated success; this demo field is evaluated only in the browser and is not sent to the server. Never enter a real Aadhaar number, phone number, or OTP. The simulated result must not be used to grant access.

## Run locally (Windows PowerShell)

```powershell
python -m pip install -r requirements.txt
python -m unittest -v
python app.py
```

Open `http://127.0.0.1:5000`. Accept the demo consent, type the fictional value `000000000000` (or cancel), and the server runs the simulated check described below.

## What the simulated check does (`encrypt.py`)

The scenario is a bank verifying a new customer. For the fictional customer, `encrypt.py` builds a request shaped like UIDAI Authentication API 2.5 (Rev 1) and sends it to a mock UIDAI in the same process:

1. The PID (identity data) is encrypted with AES-256-GCM under a fresh session key; the nonce and AAD come from the timestamp.
2. The session key is wrapped with an RSA-2048 key (RSA/ECB/PKCS1Padding).
3. `Hmac` is the SHA-256 of the PID, encrypted with the session key.
4. The "AUA" signs the request; the mock UIDAI checks the signature, decrypts, checks the timestamp and duplicates (errors 561, 562, 563), checks the hash (564), matches the record, and returns a signed `ret="y|n"`.

All keys are generated in memory at start-up and nothing is sent to UIDAI. Simplification: the signature covers the request text directly instead of W3C XML-DSig. `python -m unittest -v` covers the tamper, replay and expiry cases.

## Connecting an authorized provider

There is no universal public Aadhaar authentication endpoint that this sample can safely call. Before implementing live verification, obtain authorization and the integration guide from your authorized provider. Adapt `/auth/start` to create a provider transaction and redirect the user to the provider-hosted flow. Implement the provider's documented server-to-server callback and validate its signature, transaction/state, audience, expiry, and one-time use before accepting a result. Do not trust a browser-supplied success flag.

Do not collect or log Aadhaar numbers or OTPs in this application. Use provider-issued transaction references, request only permitted data with informed consent, encrypt any required data, limit retention/access, redact logs, and offer an alternate verification path. Have your compliance team confirm applicable UIDAI and privacy requirements.

Set `FLASK_SECRET_KEY` to a cryptographically random secret in deployed environments and set `COOKIE_SECURE=true` when serving over HTTPS. Demo sessions are signed, expire after five minutes, and are stored in the signed browser session so they work across Cloud Run instances. The service remains a simulation and must not be used to grant access based on identity.

## Deploy to Firebase Hosting

Firebase Hosting serves the public URL and rewrites application requests to the Flask container on Cloud Run. This deployment is still only the mock demo, not Aadhaar verification. Firebase CLI, Google Cloud CLI, a Firebase project on the Blaze plan, billing enabled, and permission to deploy Cloud Run services are required.

1. If needed, install the Google Cloud CLI and Node.js, then open a new PowerShell window and install Firebase CLI:

   ```powershell
   winget install --id Google.CloudSDK -e
   winget install --id OpenJS.NodeJS.LTS -e
   npm install --global firebase-tools
   ```

2. Authenticate both CLIs:

   ```powershell
   firebase login
   gcloud auth login
   ```

3. Set your Firebase project in the current shell:

   ```powershell
   $ProjectId = "YOUR_FIREBASE_PROJECT_ID"
   gcloud config set project $ProjectId
   ```

4. Generate a strong Flask session key and store it in Secret Manager:

   ```powershell
   $SecretBytes = New-Object byte[] 48
   [System.Security.Cryptography.RandomNumberGenerator]::Fill($SecretBytes)
   $FlaskSecret = [Convert]::ToBase64String($SecretBytes)
   $SecretFile = Join-Path $env:TEMP "verifyly-flask-secret.txt"
   [System.IO.File]::WriteAllText($SecretFile, $FlaskSecret)
   gcloud secrets create flask-secret-key --replication-policy automatic --data-file $SecretFile --project $ProjectId
   Remove-Item $SecretFile -Force
   ```

   Keep the generated secret private. If you already created this Secret Manager secret, use `gcloud secrets versions add flask-secret-key --data-file $SecretFile --project $ProjectId` instead of `gcloud secrets create`.

5. Grant the Cloud Run runtime service account access to the secret and deploy the backend:

   ```powershell
   $ProjectNumber = (gcloud projects describe $ProjectId --format="value(projectNumber)").Trim()
   $RuntimeServiceAccount = "$ProjectNumber-compute@developer.gserviceaccount.com"
   gcloud secrets add-iam-policy-binding flask-secret-key --member="serviceAccount:$RuntimeServiceAccount" --role="roles/secretmanager.secretAccessor" --project $ProjectId
   gcloud run deploy verifyly-demo --source . --region us-central1 --allow-unauthenticated --set-env-vars "APP_ENV=production,COOKIE_SECURE=true" --set-secrets "FLASK_SECRET_KEY=flask-secret-key:latest"
   ```

6. Deploy the Firebase Hosting frontend and rewrite:

   ```powershell
   firebase deploy --only hosting --project $ProjectId
   ```

Firebase prints the public `web.app` URL after deployment. The Hosting rewrite in `firebase.json` expects the Cloud Run service name `verifyly-demo` in `us-central1`.
