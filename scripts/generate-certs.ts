import fs from 'fs';
import path from 'path';
import forge from 'node-forge';

const CERTS_DIR = path.join(__dirname, '..', 'certs');

// Ensure certs directory
if (!fs.existsSync(CERTS_DIR)) {
  fs.mkdirSync(CERTS_DIR, { recursive: true });
}

console.log('Generating mTLS certificates...');

// Generate CA cert
const generateCA = (): { cert: forge.pki.Certificate; key: forge.pki.PrivateKey } => {
  console.log('Generating CA certificate...');

  const keys = forge.pki.rsa.generateKeyPair(4096);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName', value: 'Zero Trust Gateway CA' },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'California' },
    { name: 'localityName', value: 'San Francisco' },
    { name: 'organizationName', value: 'Zero Trust Security' },
    { shortName: 'OU', value: 'Security Operations' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
      critical: true,
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
      critical: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
  ]);

  cert.sign(keys.privateKey, forge.md.sha384.create());

  return { cert, key: keys.privateKey };
};

// Generate server cert
const generateServerCert = (
  caCert: forge.pki.Certificate,
  caKey: forge.pki.PrivateKey
): { cert: forge.pki.Certificate; key: forge.pki.PrivateKey } => {
  console.log('Generating server certificate...');

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 2);

  const attrs = [
    { name: 'commonName', value: 'zero-trust-gateway' },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'California' },
    { name: 'localityName', value: 'San Francisco' },
    { name: 'organizationName', value: 'Zero Trust Security' },
    { shortName: 'OU', value: 'API Gateway' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(caCert.subject.attributes);

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
    },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'localhost' },
        { type: 2, value: 'zero-trust-gateway' },
        { type: 2, value: '*.local' },
        { type: 7, ip: '127.0.0.1' },
        { type: 7, ip: '::1' },
      ],
    },
    {
      name: 'subjectKeyIdentifier',
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: true,
    },
  ]);

  cert.sign(caKey as forge.pki.rsa.PrivateKey, forge.md.sha256.create());

  return { cert, key: keys.privateKey };
};

// Generate client cert
const generateClientCert = (
  caCert: forge.pki.Certificate,
  caKey: forge.pki.PrivateKey,
  clientName: string
): { cert: forge.pki.Certificate; key: forge.pki.PrivateKey } => {
  console.log(`Generating client certificate for ${clientName}...`);

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = String(Math.floor(Math.random() * 1000000));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const attrs = [
    { name: 'commonName', value: clientName },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'California' },
    { name: 'localityName', value: 'San Francisco' },
    { name: 'organizationName', value: 'Zero Trust Security' },
    { shortName: 'OU', value: 'Microservices' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(caCert.subject.attributes);

  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      critical: true,
    },
    {
      name: 'extKeyUsage',
      clientAuth: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: true,
    },
  ]);

  cert.sign(caKey as forge.pki.rsa.PrivateKey, forge.md.sha256.create());

  return { cert, key: keys.privateKey };
};

// Write certs to files
const writeCert = (filename: string, cert: forge.pki.Certificate): void => {
  const pem = forge.pki.certificateToPem(cert);
  fs.writeFileSync(path.join(CERTS_DIR, filename), pem);
  console.log(`Written: ${filename}`);
};

const writeKey = (filename: string, key: forge.pki.PrivateKey): void => {
  const pem = forge.pki.privateKeyToPem(key);
  fs.writeFileSync(path.join(CERTS_DIR, filename), pem);
  console.log(`Written: ${filename}`);
};

// Main
try {
  // Generate CA
  const ca = generateCA();
  writeCert('ca.crt', ca.cert);
  writeKey('ca.key', ca.key);

  // Generate server cert
  const server = generateServerCert(ca.cert, ca.key);
  writeCert('server.crt', server.cert);
  writeKey('server.key', server.key);

  // Generate client certs for services
  const services = ['users-service', 'products-service', 'orders-service', 'inventory-service'];

  for (const service of services) {
    const client = generateClientCert(ca.cert, ca.key, service);
    writeCert(`${service}.crt`, client.cert);
    writeKey(`${service}.key`, client.key);
  }

  // Create CA + server bundle
  const bundle =
    forge.pki.certificateToPem(server.cert) + forge.pki.certificateToPem(ca.cert);
  fs.writeFileSync(path.join(CERTS_DIR, 'server-bundle.crt'), bundle);
  console.log('Written: server-bundle.crt');

  console.log('\nAll certificates generated successfully.');
  console.log(`Certificates saved in: ${CERTS_DIR}`);
  console.log('\nGenerated files:');
  fs.readdirSync(CERTS_DIR).forEach(file => {
    console.log(`  - ${file}`);
  });
} catch (error) {
  console.error('Error generating certificates:', error);
  process.exit(1);
}
