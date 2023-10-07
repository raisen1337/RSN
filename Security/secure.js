const crypto = require('crypto');
const { promises: fsPromises } = require('fs');
const path = require('path')
const RSN = {
  Security: {
    async RegenKeys() {
      const secretKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);

      try {
        await fsPromises.writeFile('secretKey.enc', secretKey);
        await fsPromises.writeFile('iv.enc', iv);
        console.log('SecretKey and IV encrypted and saved to files.');
      } catch (error) {
        console.error('Error while saving encrypted secretKey and IV:', error);
      }
    },
   
    JSON: {
      async isRSNEncrypted(encryptedData) {
        try {
          const { iv, secretKey } = await this.get_enc();
      
          const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.from(iv, 'hex'));
          let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
          decrypted += decipher.final('utf-8');
          // Check the signature header
          const signature = 'RSN_ENCRYPTED:';
          return decrypted.startsWith(signature);
        } catch (error) {
          throw new Error('Error while decrypting data:', error);
        }
      },
      
      async readEncryptedSecretKeyAndIV() {
        try {
          const secretKey = await fsPromises.readFile('secretKey.enc');
          const iv = await fsPromises.readFile('iv.enc');
          return { secretKey, iv };
        } catch (error) {
          throw new Error('Error while reading encrypted secretKey and IV:', error);
        }
      },
  
      async get_enc() {
        try {
          const { iv, secretKey } = await this.readEncryptedSecretKeyAndIV();
          return { iv: iv.toString('hex'), secretKey: secretKey.toString('hex') };
        } catch (error) {
          throw new Error('Error:', error.message);
        }
      },
  
      async encrypt(data) {
        try {
          const { iv, secretKey } = await this.get_enc();
      
          // Serialize the data to JSON
          const jsonData = JSON.stringify(data);
      
          // Add a signature header to indicate encryption by RSN
          const contentToEncrypt = 'RSN_ENCRYPTED:' + jsonData;
      
          const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.from(iv, 'hex'));
          let encrypted = cipher.update(contentToEncrypt, 'utf-8', 'hex');
          encrypted += cipher.final('hex');
      
          return encrypted;
        } catch (error) {
          console.error('File is already encrypted or an error occured.');
        }
      },
      
      async decrypt(encryptedData) {
        try {
          const { iv, secretKey } = await this.get_enc();
      
          const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.from(iv, 'hex'));
          let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
          decrypted += decipher.final('utf-8');
      
          // Check the signature header
          const signature = 'RSN_ENCRYPTED:';
          if (decrypted.startsWith(signature)) {
            // Remove the header to get the original content
            decrypted = decrypted.substring(signature.length);
            
            return JSON.parse(decrypted);
          } else {
            throw new Error('Invalid RSN encrypted data.');
          }
        } catch (error) {
          console.error('File is already decrypted or an error occured.');
        }
      }
      
    },
    File: {
      
      async isRSNEncrypted(filePath) {
        const { iv, secretKey } = await RSN.Security.JSON.get_enc();
  
        // Read the encrypted file content as a buffer
        const encryptedContent = await fsPromises.readFile(filePath);
  
        // Decrypt the file content
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.from(iv, 'hex'));
        let decryptedContent = decipher.update(encryptedContent);
        decryptedContent = Buffer.concat([decryptedContent, decipher.final()]);
  
        // Check the signature header
        const header = Buffer.from('RSN_ENCRYPTED:', 'utf-8');
        if (decryptedContent.slice(0, header.length).equals(header)) {
          return true
        } else {
          return false
        }
      },
      async encrypt(filePath) {
        try {
          const { iv, secretKey } = await RSN.Security.JSON.get_enc();
    
          // Read the file content as a buffer
          const fileContent = await fsPromises.readFile(filePath);
    
          // Add a signature header to indicate encryption by RSN
          const header = Buffer.from('RSN_ENCRYPTED:', 'utf-8');
          const contentToEncrypt = Buffer.concat([header, fileContent]);
    
          const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.from(iv, 'hex'));
          let encryptedContent = cipher.update(contentToEncrypt);
          encryptedContent = Buffer.concat([encryptedContent, cipher.final()]);
    
          // Extract the file extension and create a new file name with the "_enc.rar" suffix
          const ext = path.extname(filePath);
          const encryptedFilePath = filePath.replace(ext, `${ext}`);
    
          // Save the encrypted content to a new file
          await fsPromises.writeFile(encryptedFilePath, encryptedContent);
          console.log('File encrypted and saved as', encryptedFilePath);
        } catch (error) {
          console.error('File is already encrypted or an error occured.');
        }
      },
      async decrypt(filePath) {
        try {
          const { iv, secretKey } = await RSN.Security.JSON.get_enc();
    
          // Read the encrypted file content as a buffer
          const encryptedContent = await fsPromises.readFile(filePath);
    
          // Decrypt the file content
          const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), Buffer.from(iv, 'hex'));
          let decryptedContent = decipher.update(encryptedContent);
          decryptedContent = Buffer.concat([decryptedContent, decipher.final()]);
    
          // Check the signature header
          const header = Buffer.from('RSN_ENCRYPTED:', 'utf-8');
          if (decryptedContent.slice(0, header.length).equals(header)) {
            // Remove the header to get the original content
            decryptedContent = decryptedContent.slice(header.length);
    
            // Extract the file extension and create a new file name with the ".rar" extension
            const ext = path.extname(filePath);
            const decryptedFilePath = filePath.replace('', '');
    
            // Save the decrypted content to a new file
            await fsPromises.writeFile(decryptedFilePath, decryptedContent);
            console.log('File decrypted and saved as', decryptedFilePath);
          } else {
            throw new Error('Invalid RSN encrypted file.');
          }
        } catch (error) {
          console.error('File is already decrypted or an error occured.');
        }
      }
    }
    }
};

module.exports = RSN