// setup-keystore.js
const { saveEncryptedKey } = require('./keystore');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: true
});

console.log('🔐 Generador de keystore cifrado para el relayer\n');

rl.question('Introduce la clave privada del relayer (con o sin 0x): ', (privateKey) => {
  rl.question('Crea una contraseña maestra (segura, no la pierdas): ', (password) => {
    rl.question('Confirma la contraseña: ', (confirmPassword) => {
      if (password !== confirmPassword) {
        console.error('❌ Las contraseñas no coinciden. Abortando.');
        rl.close();
        process.exit(1);
      }
      saveEncryptedKey(privateKey.trim(), password);
      console.log('\n✅ Keystore generado exitosamente.');
      console.log('📁 Archivo: relayer.key.enc');
      console.log('🔐 Contraseña: <la que acabas de ingresar>');
      console.log('\n⚠️  IMPORTANTE:');
      console.log('   - Guarda esta contraseña en un lugar seguro.');
      console.log('   - Nunca subas el archivo .key.enc a Git.');
      console.log('   - En producción, define KEYSTORE_PASSWORD como variable de entorno secreta.\n');
      rl.close();
    });
  });
});

rl.on('close', () => process.exit(0));