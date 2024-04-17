//
//  ViewController.swift
//  CryptoSwiftDemo
//
//  Created by Jyotsna jayanteyee Pandey on 15/04/24.
//

import UIKit
import CryptoSwift
//import CommonCrypto
import CryptoKit



class ViewController: UIViewController {


    var demoString = "FZ4xwtkUVN6a5KeKdsmp6x9YtzjwF2S01t7zVUn0dHUgJj8OKV5CT+B359xOwQofK54bFqJhVtG7j7UOEek="
    var key = "111111"
    var plainText = "Hello, AES in GCM!"
    let SALT_LENGTH = 16
    let IV_LENGTH = 12
    let encriptedPos =  28
    let remainingLengh = 0
    var encriptedString = ""
    var decrptedptedString = ""
    func generateRandomSaltdata(length: Int) -> Data {
        var data = Data(count: length)
        _ = data.withUnsafeMutableBytes { mutableBytes in
            if let baseAddress = mutableBytes.baseAddress {
                let pointer = baseAddress.bindMemory(to: UInt8.self, capacity: length)
                _ = SecRandomCopyBytes(kSecRandomDefault, length, pointer)
            }
        }
        return data
    }
    func generateRandomSalt(length: Int) -> [UInt8] {
        var salt = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &salt)
        return salt
    }
    func getRandomNonce1(length: Int) throws -> Data {
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, length, $0)
        }
        guard result == errSecSuccess else {
            throw NSError(domain: "com.example", code: Int(result), userInfo: nil)
        }
        return data
    }
    func getRandomNonce(length: Int) throws -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: length)
        let result = SecRandomCopyBytes(kSecRandomDefault, length, &nonce)
        guard result == errSecSuccess else {
            throw NSError(domain: "com.example", code: Int(result), userInfo: nil)
        }
        return nonce
    }

    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        
        
        do {
            let decryptedText = try EncryptionManager.shared.decryptAesGcmBase64Text(encryptedText: demoString, key: key)
                    print("Decrypted text: \(decryptedText)")
                } catch {
                    debugPrint("some issue is happening decroption")
                }
        
        
        do {
            let decryptedText = try EncryptionManager.shared.encryptTextAesGcm(plainText: plainText, key:key)
            print("encrpted text: \(decryptedText)")
        } catch {
            debugPrint("some issue is happening decroption")

        }
        
       
            
           
        
        
       
        
        
       // EncryptionManager().cryptoDemoCipherText()
       // self.encrptData(plainText: plainText, keyString: key)


//        do {
//            let decryptedText = try decrypt(encryptedText: demoString)
//            print("Decrypted text: \(decryptedText)")
//        } catch {
//            print("Error: \(error)")
//        }
    }
    
    
    
    
    
    
    
    // MARK :decription
    
//    func getAESKeyFromPassword(password: String, salt: Data) throws -> Data {
//        var derivedKey = Data(count: kCCKeySizeAES256)
//        let status = password.withCString { passwordPtr in
//            salt.withUnsafeBytes { saltPtr in
//                CCKeyDerivationPBKDF(
//                    CCPBKDFAlgorithm(kCCPBKDF2),
//                    passwordPtr,
//                    password.count,
//                    saltPtr.baseAddress?.assumingMemoryBound(to: Int8.self),
//                    salt.count,
//                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
//                    UInt32(10000),
//                    &derivedKey,
//                    derivedKey.count
//                )
//            }
//        }
//        guard status == kCCSuccess else {
//            throw NSError(domain: "com.example", code: Int(status), userInfo: nil)
//        }
//        return derivedKey
//    }
    
    
   
    func decrypt(encryptedText: String) throws -> String {
            let tagLengthInBits = 128
            let tagLengthInBytes = tagLengthInBits / 8
            let trimmedText = encryptedText.trimmingCharacters(in: .whitespacesAndNewlines)
            let encryptedData = Data(base64Encoded: trimmedText)!
            // Extract the salt, IV, and encrypted data
            let salt = encryptedData[..<SALT_LENGTH]
            let iv = encryptedData[SALT_LENGTH..<(SALT_LENGTH + IV_LENGTH)]
            let encrypted = encryptedData[(SALT_LENGTH + IV_LENGTH  )...]
            let saltData: Array<UInt8> = Array(salt)
            let password: Array<UInt8> = Array(key.utf8)
            let encryptedArray : Array<UInt8> = Array(encrypted)
            let Ivarray : Array<UInt8> = Array(iv)
            let gcm = GCM(iv: Ivarray, mode: .combined)
            guard let  Secretkey = try? PKCS5.PBKDF2(password: password, salt: saltData, iterations: 1000, keyLength: 32, variant: .sha2(.sha512)).calculate() else {
            return "failed"
            }
       let aes = try AES(key: Secretkey, blockMode: gcm, padding: .noPadding)
       guard let content = try? aes.decrypt(encryptedArray) else {
            return "failed"
        }
        let arrData : Data = Data(content)
        if  let stringValue = String(data: arrData, encoding: .utf8) {
            decrptedptedString = stringValue
        }
        return decrptedptedString
    }

    // MARK :encryption

    func encrptData(plainText: String,keyString:String){
        do {
            // In combined mode, the authentication tag is directly appended to the encrypted message. This is usually what you want.
            
            var ciphertextInput = Data(count: plainText.count)

            let salt = generateRandomSalt(length: SALT_LENGTH)
            let iv = try getRandomNonce(length: IV_LENGTH)
            let password: Array<UInt8> = Array(keyString.utf8)
            let plainTextarray: Array<UInt8> = Array(plainText.utf8)
            guard let  Secretkey = try? PKCS5.PBKDF2(password: password, salt: salt, iterations: 1000, keyLength: 32, variant: .sha2(.sha512)).calculate() else {
                return
             }
            let gcm = GCM(iv: iv, mode: .combined)
            
            let aes = try AES(key: Secretkey, blockMode: gcm, padding: .noPadding)
            
       
            let encrypted = try aes.encrypt(plainTextarray)
            let tag = gcm.authenticationTag
            let arrData : Data = Data(encrypted)
            let data = arrData.base64EncodedString()
            let cipherData = Data(salt + iv + encrypted)
            let ciphertextString = cipherData.base64EncodedString()

            print("Ciphertext: \(ciphertextString ?? "")")
            do {
                let decryptedText = try decrypt(encryptedText: ciphertextString)
                print("Decrypted output: \(decryptedText)")
            } catch {
                print("Error: \(error)")
            }
            
        } catch {
            print("encryption output: failed")
        }
        
        
    }
    
    func dataToHexString(data: Data) -> String
    {
        let hexString:String = data.map { String(format: "%02x", $0) }.joined(separator: "")
        return hexString;
    }
    func decodeAESGCMBase64IBM(encodedString: String,hexKey:String) -> String  {
        var plainText:String? = nil;
        
        
        guard let decodedData = Data(base64Encoded: encodedString) else {
            print("Invalid Base64 encoded string")
            return "failed"
            
        }
        var offset = 0
        print("Offset: \(offset)")
        // Extract the salt
        let salt = decodedData.subdata(in: offset..<offset+Int(16))
        let saltString:String = dataToHexString(data: salt)
        
        offset += Int(16)
        // Extract the IV (Initialization Vector)
        let iv = decodedData.subdata(in: offset..<offset+12)
        let ivstring:String = dataToHexString(data: iv)
        let hexIV:String = self.generateRandomHex(bytelength: 16)
        offset += 12
        // Extract the ciphertext
        let ciphertextLength = decodedData.count - offset - 16 // Assuming authentication tag length is 16 bytes
        let cipherHexStr = decodedData.subdata(in: offset..<offset+ciphertextLength)
        
        let ciphertext:String = dataToHexString(data: cipherHexStr)
        
        offset += ciphertextLength
        // Extract the authentication tag
        let tag = decodedData.subdata(in: offset..<offset+16)
        // Assuming authentication tag length is 16 bytes
        let tagString:String = dataToHexString(data: cipherHexStr)
        let password: Array<UInt8> = Array(key.utf8)
        let encoded: Array<UInt8> = Array(encodedString.utf8)
        let Ivarray : Array<UInt8> = Array(ivstring.utf8)
        let saltData: Array<UInt8> = Array(saltString.utf8)
        let globalKey: Array<UInt8> = Array(key.utf8)
        let tagarray: Array<UInt8> = Array(tagString.utf8)
        let encrypted = Data(cipherHexStr)
        let encryptedArray : Array<UInt8> = Array(ciphertext.utf8)
        let plainArray : Array<UInt8> = Array("Hello, AES in GCM!".utf8)
        let encryptedArrayOriginal : Array<UInt8> = Array(encodedString.utf8)
        guard let  Secretkey = try? PKCS5.PBKDF2(password: password, salt: saltData, iterations: 1000, keyLength: 32, variant: .sha2(.sha512)).calculate() else {
            return "failed"
         }
        
        do {
            let gcm = GCM(iv: Ivarray, mode: .combined)
            let aes = try AES(key: Secretkey, blockMode: gcm, padding: .noPadding)
            let encrypted = try aes.encrypt(plainArray)
            let tag = gcm.authenticationTag
            guard let content = try? aes.decrypt(encrypted) else {
                 return "failed"
             }
            print("output")

            print("result is \(Data(content))")
            let arrData = Data(content)
            if  let string = String(data: arrData, encoding: .utf8) {
                print("array data to string after decription ")

                print(string)
            }

        } catch {
            return "failed"
        }
        
        do {
            let gcm = GCM(iv: Ivarray, mode: .combined)
           //  gcm.authenticationTag = tagarray
            let aes = try AES(key: Secretkey, blockMode: gcm, padding: .noPadding)
           guard let content = try? aes.decrypt(encryptedArray) else {
                return "failed"
            }

            print(content)

        } catch {
            // failed
            return "failed"
        }
//        guard let aes = try? AES(key: Secretkey, blockMode: CBC(iv: Ivarray), padding: .noPadding) else {
//            return "0"
//        }
//        guard  let decryptedBytes = try? aes.decrypt(encrypted.bytes) else
//        {
//            return "0"
//        }
//        let decryptedData = Data(decryptedBytes)
//        plainText = String.init(data: decryptedData, encoding: String.Encoding.utf8)
//        print("test, plainText \(String(describing: plainText))")
        return plainText!
    
        
        }
    
     func generateRandomHex(bytelength: Int) -> String
    {
        let stringLength : Int = bytelength * 2
        let letters : NSString = "abcdef0123456789"
        let len = UInt32(letters.length)
        
        var randomString:String = ""
        
        for _ in 0 ..< stringLength
        {
            let rand = arc4random_uniform(len)
            var nextChar = letters.character(at: Int(rand))
            randomString += NSString(characters: &nextChar, length: 1) as String
        }
        
        //prevent null block.
        randomString = randomString.replacingOccurrences(of: "00", with: "11")
        
        return randomString
    }
     func encrpt(plainText: String) throws -> String {
        return encriptedString
    }
    // MARK : decryption

    
    func encryptAESGCM(message: Data, key: SymmetricKey) throws -> (ciphertext: Data, tag: Data) {
        // Generate a random initialization vector
        let iv = AES.GCM.Nonce()

        // Create an AES-GCM sealed box
        let sealedBox = try AES.GCM.seal(message, using: key, nonce: iv)

        // Extract ciphertext and tag from the sealed box
        let ciphertext = sealedBox.ciphertext
        let tag = sealedBox.tag

        return (ciphertext, tag)
    }

//    func decryptAESGCM(ciphertext: Data, tag: Data, key: SymmetricKey) throws -> Data {
//        // Create a sealed box using the provided ciphertext, tag, and key
//        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(), ciphertext: ciphertext, tag: tag)
//
//        // Decrypt the sealed box using the key
//        let decryptedData = try AES.GCM.open(sealedBox, using: key)
//
//        return decryptedData
//    }

    
   



}

