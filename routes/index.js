var express = require('express');
var router = express.Router();
const crypto = require('crypto');
require('dotenv').config();
const { HASHIV, HASHKEY, MerchantID, Version, Host, ReturnUrl, NotifyUrl} = process.env;

/* 建立訂單 */

const orders = {}; //沒建資料庫，訂單先存這。
const RespondType = 'JSON';

router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express', Host });
});


// 建立一筆訂單 
router.post('/createOrder', (req, res) => {
  const data = req.body;
  console.log(data);

  const TimeStamp = Math.round(new Date().getTime() / 1000);
  console.log(TimeStamp);

  orders[TimeStamp] = {
    ...data,
    TimeStamp,
    MerchantOrderNo: TimeStamp,
  };

  console.log(orders[TimeStamp]);
  return res.json(orders[TimeStamp]);
});
 
//確認訂單
router.get('/check', function (req, res, next) {
  res.render('check', { title: 'Express', Host });
});

router.get('/order/:id', (req,res) => {
  const { id } = req.params;
  const order = orders[id];

  const aesEncrypt = create_mpg_aes_encrypt(order);
  console.log('aesEncrypt', aesEncrypt); //交易資料
  const shaEncrypt = create_mpg_sha_encrypt(order);
  console.log('shaEncrypt', shaEncrypt); //驗證用
  

  res.json({
    order,
    aesEncrypt,
    shaEncrypt
  });
});

module.exports = router;

function genDataChain(order) {
  return `MerchantID=${MerchantID}&RespondType=${RespondType}&TimeStamp=${order.TimeStamp}&
    Version=${Version}&MerchantOrderNo=${order.MerchantOrderNo}&
    Amt=${order.Amt}&ItemDesc=${encodeURIComponent(order.ItemDesc)}&NotifyURL=${encodeURIComponent(NotifyUrl)}`;
};


// 對應文件 P16：使用 aes 加密 （商品資料）
// $edata1=bin2hex(openssl_encrypt($data1, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv));
function create_mpg_aes_encrypt(TradeInfo) {
 const encrypt = crypto.createCipheriv('aes-256-cbc', HASHKEY, HASHIV);
 const enc = encrypt.update(genDataChain(TradeInfo), 'utf8', 'hex');
 return enc + encrypt.final('hex');
}


// 對應文件 P17：使用 sha256 加密
// $hashs="HashKey=".$key."&".$edata1."&HashIV=".$iv;
function create_mpg_sha_encrypt(aesEncrypt) {
  const sha = crypto.createHash('sha256');
  const plainText = `HashKey=${HASHKEY}&${aesEncrypt}&HashIV=${HASHIV}`;

  return sha.update(plainText).digest('hex').toUpperCase();
};

// 將 aes 解密
function create_mpg_aes_decrypt(TradeInfo) {
  const decrypt = crypto.createDecipheriv('aes256', HASHKEY, HASHIV);
  decrypt.setAutoPadding(false);
  const text = decrypt.update(TradeInfo, 'hex', 'utf8');
  const plainText = text + decrypt.final('utf8');
  const result = plainText.replace(/[\x00-\x20]+/g, '');
  return JSON.parse(result);
};