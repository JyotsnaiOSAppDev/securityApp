//
//  EncryptionManager.swift
//  CryptoSwiftDemo
//
//  Created by Jyotsna jayanteyee Pandey on 16/04/24.
//
import CryptoSwift
import CryptoKit
import Foundation
class EncryptionManager {
    static let shared = EncryptionManager()
    let SALT_LENGTH = 16
    let IV_LENGTH = 12
    let encriptedPos =  28
    let remainingLengh = 0
    var encriptedString = ""
    var decrptedptedString = ""
      private init() {}
    func getRandomNonce(length: Int) throws -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: length)
        let result = SecRandomCopyBytes(kSecRandomDefault, length, &nonce)
        guard result == errSecSuccess else {
            throw NSError(domain: "com.example", code: Int(result), userInfo: nil)
        }
        return nonce
    }
    func generateRandomSalt(length: Int) -> [UInt8] {
        var salt = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &salt)
        return salt
    }
   
    
      func decryptAesGcmBase64Text(encryptedText: String,key: String) throws -> String {
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
     func encryptTextAesGcm(plainText: String,key:String){
        do {
            let salt = generateRandomSalt(length: SALT_LENGTH)
            let iv = try getRandomNonce(length: IV_LENGTH)
            let password: Array<UInt8> = Array(key.utf8)
            let plainTextarray: Array<UInt8> = Array(plainText.utf8)
            guard let  Secretkey = try? PKCS5.PBKDF2(password: password, salt: salt, iterations: 1000, keyLength: 32, variant: .sha2(.sha512)).calculate() else {
                return
             }
            let gcm = GCM(iv: iv, mode: .combined)
            let aes = try AES(key: Secretkey, blockMode: gcm, padding: .noPadding)
                        let encrypted = try aes.encrypt(plainTextarray)
            let arrData : Data = Data(encrypted)
            let cipherData = Data(salt + iv + encrypted)
            let ciphertextString = cipherData.base64EncodedString()
           // print("Ciphertext: \(ciphertextString ?? "")")
        } catch {
            print("encryption output: failed")
        }
      }
    
  //  calling of this file
//    do {
//        let decryptedText = try EncryptionManager.shared.decryptAesGcmBase64Text(encryptedText: demoString, key: key)
//                print("Decrypted text: \(decryptedText)")
//            } catch {
//                debugPrint("some issue is happening decroption")
//            }
//    
//    
//    do {
//        let decryptedText = try EncryptionManager.shared.encryptTextAesGcm(plainText: plainText, key:key)
//        print("encrpted text: \(decryptedText)")
//    } catch {
//        debugPrint("some issue is happening decroption")
//
//    }
    

    
}
