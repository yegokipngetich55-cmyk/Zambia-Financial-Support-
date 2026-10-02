"use strict";

require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const ONTECH_BASE_URL =
  process.env.ONTECH_BASE_URL ||
  "https://payments.ontech.co.zm/api/v1";

const ONTECH_API_KEY = process.env.ONTECH_API_KEY;
const ONTECH_WEBHOOK_SECRET = process.env.ONTECH_WEBHOOK_SECRET;

if (!ONTECH_API_KEY) {
  console.warn("WARNING: ONTECH_API_KEY is not configured.");
}

if (!ONTECH_WEBHOOK_SECRET) {
  console.warn("WARNING: ONTECH_WEBHOOK_SECRET is not configured.");
}

app.use(express.json());

/*
 * Serve your frontend files from the same project.
 *
 * Put payment.html, delivery.html, page1.html, page2.html,
 * page3.html, etc. inside the public folder.
 */
app.use(express.static(path.join(__dirname, "public")));


/*
 * Basic Zambian phone validation.
 *
 * Accepted:
 * 09XXXXXXXX
 * 260XXXXXXXXX
 */
function normalizeZambianPhone(phone) {
  let value = String(phone || "").replace(/\s+/g, "");

  if (/^0\d{9}$/.test(value)) {
    return value;
  }

  if (/^260\d{9}$/.test(value)) {
    return value;
  }

  throw new Error(
    "Enter a valid Zambian mobile number, for example 0971234567."
  );
}


/*
 * Generate a unique idempotency key.
 */
function createIdempotencyKey() {
  return "zsf-" + crypto.randomUUID();
}


/*
 * POST /api/pay
 *
 * The browser sends the selected amount, fee and phone.
 * The secret API key is used ONLY here on the server.
 */
app.post("/api/pay", async (req, res) => {
  try {
    if (!ONTECH_API_KEY) {
      return res.status(500).json({
        success: false,
        message: "Payment gateway is not configured on the server."
      });
    }

    const {
      amount,
      phone,
      customer_name,
      reference
    } = req.body || {};

    const paymentAmount = Number(amount);

    if (!Number.isFinite(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid payment amount."
      });
    }

    const normalizedPhone = normalizeZambianPhone(phone);

    const internalReference =
      String(reference || "").trim() ||
      `ZSF-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;

    const idempotencyKey = createIdempotencyKey();

    const gatewayResponse = await fetch(
      `${ONTECH_BASE_URL}/pay/collect`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": ONTECH_API_KEY,
          "X-Idempotency-Key": idempotencyKey
        },
        body: JSON.stringify({
          amount: Number(paymentAmount.toFixed(2)),
          phone: normalizedPhone,
          reference: internalReference,
          description: "Zambia Financial Support sample application",
          customer_name:
            String(customer_name || "Applicant").trim()
        })
      }
    );

    const rawText = await gatewayResponse.text();

    let gatewayData;

    try {
      gatewayData = JSON.parse(rawText);
    } catch {
      gatewayData = {
        detail: rawText || "Invalid response from payment gateway."
      };
    }

    if (!gatewayResponse.ok) {
      return res.status(gatewayResponse.status).json({
        success: false,
        message:
          gatewayData.detail ||
          gatewayData.message ||
          "The payment gateway rejected the request."
      });
    }

    return res.json({
      success: true,
      transaction_id: gatewayData.transaction_id,
      status: gatewayData.status,
      message:
        gatewayData.message ||
        "Payment request submitted.",
      amount: gatewayData.amount,
      provider: gatewayData.provider,
      reference: internalReference
    });

  } catch (error) {
    console.error("Payment error:", error);

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "Unable to connect to the payment gateway."
    });
  }
});


/*
 * GET /api/pay/status/:transactionId
 *
 * Checks an existing Ontech transaction.
 */
app.get("/api/pay/status/:transactionId", async (req, res) => {
  try {
    if (!ONTECH_API_KEY) {
      return res.status(500).json({
        success: false,
        message: "Payment gateway is not configured."
      });
    }

    const transactionId =
      String(req.params.transactionId || "").trim();

    if (!transactionId) {
      return res.status(400).json({
        success: false,
        message: "Missing transaction ID."
      });
    }

    const gatewayResponse = await fetch(
      `${ONTECH_BASE_URL}/pay/status/${encodeURIComponent(transactionId)}`,
      {
        method: "GET",
        headers: {
          "X-API-Key": ONTECH_API_KEY
        }
      }
    );

    const rawText = await gatewayResponse.text();

    let gatewayData;

    try {
      gatewayData = JSON.parse(rawText);
    } catch {
      gatewayData = {
        detail: rawText
      };
    }

    if (!gatewayResponse.ok) {
      return res.status(gatewayResponse.status).json({
        success: false,
        message:
          gatewayData.detail ||
          gatewayData.message ||
          "Unable to check payment status."
      });
    }

    return res.json(gatewayData);

  } catch (error) {
    console.error("Status error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to check payment status."
    });
  }
});


/*
 * Webhook signature verification.
 *
 * Ontech signs JSON with alphabetically sorted top-level keys.
 */
function verifyOntechSignature(payload, signature) {
  if (!ONTECH_WEBHOOK_SECRET || !signature) {
    return false;
  }

  const sortedKeys = Object.keys(payload).sort();

  const payloadString = JSON.stringify(
    payload,
    sortedKeys
  );

  const expected = crypto
    .createHmac(
      "sha256",
      ONTECH_WEBHOOK_SECRET
    )
    .update(payloadString)
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(String(signature))
  );
}


/*
 * POST /webhooks/ontech-payment
 *
 * Ontech sends payment events here.
 */
app.post("/webhooks/ontech-payment", (req, res) => {
  try {
    const signature =
      req.headers["x-webhook-signature"];

    const payload = req.body;

    if (!verifyOntechSignature(payload, signature)) {
      console.warn("Invalid Ontech webhook signature.");

      return res
        .status(401)
        .send("Invalid signature");
    }

    const {
      event,
      transaction_id,
      amount,
      status,
      app_reference,
      customer_phone
    } = payload;

    console.log("Ontech webhook received:", {
      event,
      transaction_id,
      amount,
      status,
      app_reference,
      customer_phone
    });

    /*
     * In a production application, save the transaction
     * and its status in your database here.
     *
     * For this sample integration, the browser checks the
     * transaction status through /api/pay/status/:id.
     */

    return res.status(200).send("OK");

  } catch (error) {
    console.error("Webhook error:", error);

    return res
      .status(500)
      .send("Webhook processing error");
  }
});


/*
 * Health check
 */
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "Zambia Financial Support Ontech Sandbox",
    mode: "sandbox"
  });
});


app.listen(PORT, () => {
  console.log(
    `Server running on http://localhost:${PORT}`
  );
}); aww
