import 'dart:math';
import 'dart:typed_data';
import 'package:aes_crypt_null_safe/aes_crypt_null_safe.dart';

class Cryption {
  static var crypt = AesCrypt();

  static String encryptionText(String text) {
    //generate Random() key and initialization vector('iv')
    //and set them into AesCrypt()
    Uint8List key = Uint8List.fromList(List<int>.generate(16, (i) => Random().nextInt(256)));
    Uint8List iv = Uint8List.fromList(List<int>.generate(16, (i) => Random().nextInt(256)));
    crypt.aesSetKeys(key, iv);

    //create chunkList for storing 16-byte-blocks of message
    //each element chunkList equals one 16-byte-block of message
    List<String> chunksList = [];
    while(text.isNotEmpty) {
      chunksList.add(text.substring(0,(text.length > 16)? 16 : text.length));
      text = text.substring((text.length > 16)? 16 : text.length);
    }

    //create bytes for storing codeUnits of one 16-byte-block
    List<int> bytes = List<int>.filled(0,0,growable: true);
    for(var i = 0; i < chunksList.length; i++) {
      //one block to codeUnits
      bytes.addAll(chunksList[i].codeUnits);
      //if (bytes.length < 16) fill this bytes with zeros
      bytes.addAll(List<int>.filled(16 - chunksList[i].length, 0));
      //encrypt bytes
      Uint8List encryptedList = crypt.aesEncrypt(Uint8List.fromList(bytes));
      bytes.clear();

      if (text.isEmpty) {text = encryptedList.join(',');}
      else {text += ',' + encryptedList.join(',');}
    }

    return text;
  }

  static String decryptionText(String text) {
    try {
      if (text.isEmpty) {
        return '';
      }

      //create List<string> of ascii from input enumeration
      //example: ('97, 98, 99') => ['97', '98', '99']
      List textListStr = text.split(',');
      //List<String> to List<int>
      List<int> textList = textListStr.map((e) => int.parse(e)).toList();
      //text.clear(); :(
      text = '';

      //create chunksList for storing 16-length-List<int>
      List<List<int>> chunksList = [];
      while(textList.isNotEmpty) {
        chunksList.add(textList.sublist(0,16));
        textList.removeRange(0, 16);
      }

      for(var i = 0; i < chunksList.length; i++) {
        //decrypt
        Uint8List decryptedList = crypt.aesDecrypt(Uint8List.fromList(chunksList[i]));
        text += String.fromCharCodes(decryptedList);
      }

      return text;
    } on Exception {
      return 'please write valid code';
    }
  }
}