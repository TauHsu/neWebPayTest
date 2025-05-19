var express = require("express");
var router = express.Router();
const crypto = require("crypto");
require("dotenv").config();
const { HASHIV, HASHKEY, MerchantID, Version, Host, ReturnUrl, NotifyUrl } =
  process.env;

/* 建立訂單 */

const orders = {}; //沒建資料庫，訂單先存這。
const RespondType = "JSON";

router.get("/", function (req, res, next) {
  res.render("index", { title: "Express", Host });
});

// 建立一筆訂單
router.post("/createOrder", (req, res) => {
  const data = req.body;
  const TimeStamp = Math.round(new Date().getTime() / 1000);
  orders[TimeStamp] = {
    ...data,
    TimeStamp,
    Amt: parseInt(data.Amt),
    MerchantOrderNo: TimeStamp,
  };

  //console.log("createOrder:", TimeStamp, orders);
  return res.json(orders[TimeStamp]);
});

//確認訂單
router.get("/check", function (req, res, next) {
  res.render("check", { title: "Express", Host });
});

router.get("/order/:id", (req, res) => {
  const { id } = req.params;
  const order = orders[id];
  //console.log(order);

  const aesEncrypt = create_mpg_aes_encrypt(order);
  //console.log("aesEncrypt", aesEncrypt); //交易資料
  const shaEncrypt = create_mpg_sha_encrypt(aesEncrypt);
  //console.log("shaEncrypt", shaEncrypt); //驗證用

  res.status(200).json({
    status: true,
    data: {
      id,
      Email: order.Email,
      Amt: order.Amt,
      ItemDesc: order.ItemDesc,
      TimeStamp: order.TimeStamp,
      MerchantOrderNo: order.MerchantOrderNo,
      aesEncrypt: aesEncrypt,
      shaEncrypt: shaEncrypt,
    },
  });
});

// 交易成功：Return （可直接解密，將資料呈現在畫面上）
router.post("/newebpay/return", function (req, res, next) {
  console.log("req.body return data", req.body);
  res.render("success", { title: "Express", Host });
});

// 確認交易：Notify
router.post("/newebpay/notify", function (req, res, next) {
  console.log("req.body notify data", req.body);
  const response = req.body;

  const thisShaEncrypt = create_mpg_sha_encrypt(response.TradeInfo);
  // 使用 HASH 再次 SHA 加密字串，確保比對一致（確保不正確的請求觸發交易成功）
  if (!thisShaEncrypt === response.TradeSha) {
    console.log("付款失敗：TradeSha 不一致");
    return res.end();
  }

  // 解密交易內容
  const data = create_mpg_aes_decrypt(response.TradeInfo);
  console.log("data:", data);

  // 取得交易內容，並查詢本地端資料庫是否有相符的訂單
  if (!orders[data?.Result?.MerchantOrderNo]) {
    console.log("找不到訂單");
    return res.end();
  }

  // 交易完成，將成功資訊儲存於資料庫
  console.log("付款完成，訂單：", orders[data?.Result?.MerchantOrderNo]);

  return res.end();
});
/*
router.post("/newebpay/return", (req, res) => {
  const data = req.body;
  console.log("return:", data);
  res.end();
});

router.post("/newebpay/notify", (req, res) => {
  const data = req.body;
  console.log("nodify:", data);
  res.end();
});
*/
// 交易成功：Return （可直接解密，將資料呈現在畫面上）
router.post("/newebpay_return", function (req, res, next) {
  console.log("req.body return data", req.body);
  res.render("success", { title: "Express" });
});

// 確認交易：Notify
router.post("/newebpay_notify", function (req, res, next) {
  console.log("req.body notify data", req.body);
  const response = req.body;

  // 解密交易內容
  const data = createSesDecrypt(response.TradeInfo);
  console.log("data:", data);

  // 取得交易內容，並查詢本地端資料庫是否有相符的訂單
  console.log(orders[data?.Result?.MerchantOrderNo]);
  if (!orders[data?.Result?.MerchantOrderNo]) {
    console.log("找不到訂單");
    return res.end();
  }

  // 使用 HASH 再次 SHA 加密字串，確保比對一致（確保不正確的請求觸發交易成功）
  const thisShaEncrypt = createShaEncrypt(response.TradeInfo);
  if (!thisShaEncrypt === response.TradeSha) {
    console.log("付款失敗：TradeSha 不一致");
    return res.end();
  }

  // 交易完成，將成功資訊儲存於資料庫
  console.log("付款完成，訂單：", orders[data?.Result?.MerchantOrderNo]);

  return res.end();
});

module.exports = router;

function genDataChain(order) {
  return (
    `MerchantID=${MerchantID}&RespondType=${RespondType}&TimeStamp=${order.TimeStamp}` +
    `&Version=${Version}&MerchantOrderNo=${order.MerchantOrderNo}&Amt=${order.Amt}` +
    `&ItemDesc=${encodeURIComponent(order.ItemDesc)}&Email=${encodeURIComponent(
      order.Email
    )}`
  );

  //Amt=100&MerchantID=你的商店代號&MerchantOrderNo=訂單號碼&TimeStamp=時間戳記
}

// 對應文件 P16：使用 aes 加密 （訂單資料傳入）
// $edata1=bin2hex(openssl_encrypt($data1, "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv));
function create_mpg_aes_encrypt(TradeInfo) {
  const encrypt = crypto.createCipheriv("aes-256-cbc", HASHKEY, HASHIV);
  const enc = encrypt.update(genDataChain(TradeInfo), "utf8", "hex");
  return enc + encrypt.final("hex");
}

// 對應文件 P17：使用 sha256 加密
// $hashs="HashKey=".$key."&".$edata1."&HashIV=".$iv;
function create_mpg_sha_encrypt(aesEncrypt) {
  const sha = crypto.createHash("sha256");
  const plainText = `HashKey=${HASHKEY}&${aesEncrypt}&HashIV=${HASHIV}`;

  return sha.update(plainText).digest("hex").toUpperCase();
}

// 將 aes 解密
function create_mpg_aes_decrypt(TradeInfo) {
  const decrypt = crypto.createDecipheriv("aes256", HASHKEY, HASHIV);
  decrypt.setAutoPadding(true);
  const text = decrypt.update(TradeInfo, "hex", "utf8");
  const plainText = text + decrypt.final("utf8");
  const result = plainText.replace(/[\x00-\x20]+/g, "");
  return JSON.parse(result);
}
