import {PASSWORD, SIGNING_KEY} from "./secrets";

import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

import { createHmac } from "crypto";
import { getAuth } from "firebase-admin/auth";
import { getDatabase } from "firebase-admin/database";

admin.initializeApp();

const getUniqueKey = (serial: string) => {
	const uniqueKey = { serial: serial, signingKey: SIGNING_KEY };
	const hashedKey = createHmac("sha256", JSON.stringify(uniqueKey)).digest("hex");

	return hashedKey;
}

const timestamp = () => Math.floor(new Date().getTime() / 1000);

// This function takes the serial number and a unique key (password) from the IoT controller as an argument
// /requestNewToken?serial={serial}&key={unique_key}
//
// The unique key is generated through the IoT controller by the project group
//
// It does the following:
// 1. Validate that the serial and key match
// 2. Generate custom token
// 3. Check if we have an existing database entry for this serial number
//    If false: Create a new entry that checks for user.token.iotDevice = true
// 4. Return the user token to the IoT controller
export const requestNewToken = functions.region("europe-west1").https.onRequest(async (request, response) => {
	if(!request.query.serial || !request.query.key) {
		response.status(400).send("missing_parameter");
		return;
	}

	const serial = request.query.serial.toString();

	if(![...serial].every(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) || serial.length < 2 || serial.length > 24) {
		response.status(400).send("invalid_serial");
		return;
	}

	const expectedKey = getUniqueKey(serial);

	if(request.query.key !== expectedKey) {
		response.status(401).send("wrong_key");
		return;
	}

	// IoT controller is authenticated
	functions.logger.log(`Authentication for Iot controller ${request.query.serial} successful`);

	const db = getDatabase();
	const garden = await db.ref(`garden/${serial}`).get();

	if(garden.exists() && garden.child("last_token").exists() && garden.child("last_token_time").exists()) {
		// Token last for one hour, so create a new one if at least 50 minutes have passed
		if(timestamp() - garden.child("last_token_time").val() < 50 * 60) {
			response.send(garden.child("last_token").val());
			return;
		}
	}

	const auth = getAuth();
	const generatedTime = timestamp();
	// iotDevice identifies this user as a smart garden (instead of a real person)
	const token = await auth.createCustomToken(`garden_${serial}`, { iotDevice: true });

	await db.ref(`garden/${serial}/last_token_time`).set(generatedTime);
	await db.ref(`garden/${serial}/last_token`).set(token);

	response.send(token);
});

// This function returns a unique key for a specific serial number if the user specifies the right password
// /signSerialNumber?serial={serial}&password={password}
export const signSerialNumber = functions.region("europe-west1").https.onRequest((request, response) => {
	if(!request.query.serial || !request.query.password) {
		response.status(400).send("missing_parameter");
		return;
	}

	if(request.query.password !== PASSWORD) {
		response.status(401).send("wrong_password");
		return;
	}

	const uniqueKey = getUniqueKey(request.query.serial.toString());
	functions.logger.log(`Created a key for serial number ${request.query.serial}`);
	response.send(uniqueKey);
});
