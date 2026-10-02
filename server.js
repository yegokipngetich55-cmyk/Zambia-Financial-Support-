"use strict";

require("dotenv").config();

const express = require("express");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

const ONTECH_BASE_URL =
  process.env.ONTECH_BASE_URL ||
  "https://payments.ontech.co.zm/api/v1";

const ONTECH_API_KEY = process.env.ONTECH_API_KEY;
const ONTECH_WEBHOOK_SECRET =
  process.env.ONTECH_WEBHOOK_SECRET;

if (!ONTECH_API_KEY) {
  console.warn("WARNING: ONTECH_API_KEY is not configured.");
}

if (!ONTECH_WEBHOOK_SECRET) {
  console.warn(
    "WARNING: ONTECH_WEBHOOK_SECRET is not configured."
  );
}

app.use(express.json());

/*
|--------------------------------------------------------------------------
| Serve website files from the project root
|--------------------------------------------------------------------------
| Files such as:
| index.html
| page1.html
| page2.html
| page3.html
| payment.html
| delivery.html
| zambiafinancialsupport.jpg
|
| can all be placed beside server.js.
*/
app.use(express.static(__dirname));

/*
|--------------------------------------------------------------------------
| Home page
|--------------------------------------------------------------------------
*/
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

/*
|--------------------------------------------------------------------------
| Normalize Zambia phone number
|--------------------------------------------------------------------------
| Accepts:
| 0971234567
| 260971234567
|--------------------------------------------------------------------------
*/
function normalizeZambiaPhone(phone) {
  if (!phone) {
    return null;
  }

  const value = String(phone).trim().replace(/\s+/g, "");

  if (/^0\d{9}$/.test(value)) {
    return "260" + value.substring(1);
  }

  if (/^260\d{9}$/.test(value)) {
    return value;
  }

  return null;
}

/*
|--------------------------------------------------------------------------
| Create idempotency key
|--------------------------------------------------------------------------
*/
function createIdempotencyKey() {
  return crypto.randomUUID();
}

/*
|--------------------------------------------------------------------------
| POST /api/pay
|--------------------------------------------------------------------------
| Sends a collection request to Ontech Payments Sandbox.
|--------------------------------------------------------------------------
*/
app.post("/api/pay", async (req, res) => {
  try {
    if (!ONTECH_API_KEY) {
      return res.status(500).json({
        success: false,
        message: "Ontech API key is not configured on the server."
      });
    }

    const {
      amount,
      phone,
      reference,
      description,
      customer_name
    } = req.body || {};

    const numericAmount = Number(amount);

    if (
      !Number.isFinite(numericAmount) ||
      numericAmount <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid payment amount."
      });
    }

    const normalizedPhone = normalizeZambiaPhone(phone);

    if (!normalizedPhone) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid Zambia phone number. Use 09XXXXXXXX or 260XXXXXXXXX."
      });
    }

    const idempotencyKey = createIdempotencyKey();

    const requestBody = {
      amount: numericAmount,
      phone: normalizedPhone
    };

    if (reference) {
      requestBody.reference = String(reference);
    }

    if (description) {
      requestBody.description = String(description);
    }

    if (customer_name) {
      requestBody.customer_name = String(customer_name);
    }

    const response = await fetch(
      `${ONTECH_BASE_URL}/pay/collect`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": ONTECH_API_KEY,
          "X-Idempotency-Key": idempotencyKey
        },
        body: JSON.stringify(requestBody)
      }
    );

    const responseText = await response.text();

    let data;

    try {
      data = JSON.parse(responseText);
    } catch {
      data = {
        raw: responseText
      };
    }

    if (!response.ok) {
      console.error(
        "Ontech collection request failed:",
        response.status,
        data
      );

      return res.status(response.status).json({
        success: false,
        message:
          data.message ||
          data.error ||
          "Ontech payment request failed.",
        data
      });
    }

    return res.json({
      success: true,
      data
    });
  } catch (error) {
    console.error("Payment request error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to process the payment request.",
      error: error.message
    });
  }
});

/*
|--------------------------------------------------------------------------
| GET /api/pay/status/:transactionId
|--------------------------------------------------------------------------
| Checks the current Ontech transaction status.
|--------------------------------------------------------------------------
*/
app.get(
  "/api/pay/status/:transactionId",
  async (req, res) => {
    try {
      if (!ONTECH_API_KEY) {
        return res.status(500).json({
          success: false,
          message:
            "Ontech API key is not configured on the server."
        });
      }

      const transactionId =
        String(req.params.transactionId || "").trim();

      if (!transactionId) {
        return res.status(400).json({
          success: false,
          message: "Transaction ID is required."
        });
      }

      const response = await fetch(
        `${ONTECH_BASE_URL}/pay/status/${encodeURIComponent(
          transactionId
        )}`,
        {
          method: "GET",
          headers: {
            "X-API-Key": ONTECH_API_KEY
          }
        }
      );

      const responseText = await response.text();

      let data;

      try {
        data = JSON.parse(responseText);
      } catch {
        data = {
          raw: responseText
        };
      }

      if (!response.ok) {
        console.error(
          "Ontech status request failed:",
          response.status,
          data
        );

        return res.status(response.status).json({
          success: false,
          message:
            data.message ||
            data.error ||
            "Unable to retrieve transaction status.",
          data
        });
      }

      return res.json({
        success: true,
        data
      });
    } catch (error) {
      console.error("Status request error:", error);

      return res.status(500).json({
        success: false,
        message:
          "Unable to retrieve payment status.",
        error: error.message
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Ontech Webhook
|--------------------------------------------------------------------------
| Ontech can send payment status notifications here.
|--------------------------------------------------------------------------
*/
app.post(
  "/webhooks/ontech-payment",
  (req, res) => {
    try {
      const signature =
        req.headers["x-webhook-signature"] ||
        req.headers["x-signature"];

      if (!ONTECH_WEBHOOK_SECRET) {
        console.warn(
          "Webhook received, but ONTECH_WEBHOOK_SECRET is not configured."
        );

        return res.status(200).json({
          received: true
        });
      }

      if (!signature) {
        return res.status(401).json({
          success: false,
          message: "Missing webhook signature."
        });
      }

      const payload = req.body || {};

      /*
       * Ontech signs the JSON payload using sorted keys.
       */
      const sortedPayload = {};

      Object.keys(payload)
        .sort()
        .forEach((key) => {
          sortedPayload[key] = payload[key];
        });

      const payloadString =
        JSON.stringify(sortedPayload);

      const expectedSignature =
        crypto
          .createHmac(
            "sha256",
            ONTECH_WEBHOOK_SECRET
          )
          .update(payloadString)
          .digest("hex");

      const providedSignature =
        String(signature).replace(/^sha256=/, "");

      const expectedBuffer =
        Buffer.from(expectedSignature, "utf8");

      const providedBuffer =
        Buffer.from(providedSignature, "utf8");

      if (
        expectedBuffer.length !==
        providedBuffer.length
      ) {
        return res.status(401).json({
          success: false,
          message: "Invalid webhook signature."
        });
      }

      const validSignature =
        crypto.timingSafeEqual(
          expectedBuffer,
          providedBuffer
        );

      if (!validSignature) {
        return res.status(401).json({
          success: false,
          message: "Invalid webhook signature."
        });
      }

      console.log(
        "Verified Ontech webhook:",
        JSON.stringify(payload, null, 2)
      );

      /*
       * Payment events can be handled here if needed.
       *
       * Examples:
       * payment.success
       * payment.failed
       * payment.completed
       * payment.reversed
       */

      return res.status(200).json({
        received: true
      });
    } catch (error) {
      console.error(
        "Webhook processing error:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Webhook processing failed."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| Health check
|--------------------------------------------------------------------------
*/
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service:
      "Zambia Financial Support Ontech Sandbox",
    mode: "sandbox"
  });
});

/*
|--------------------------------------------------------------------------
| 404 handler for API routes
|--------------------------------------------------------------------------
*/
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});

/*
|--------------------------------------------------------------------------
| Start server
|--------------------------------------------------------------------------
*/
app.listen(PORT, () => {
  console.log(
    `Server running on port ${PORT}`
  );
});
