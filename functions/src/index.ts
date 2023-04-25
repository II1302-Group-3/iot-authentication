import {PASSWORD, SIGNING_KEY} from "./secrets";

import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

import { createHmac } from "crypto";
import { getAuth } from "firebase-admin/auth";

admin.initializeApp();

const getUniqueKey = (serial: string) => {
	const uniqueKey = { serial: serial, signingKey: SIGNING_KEY };
	const hashedKey = createHmac("sha256", JSON.stringify(uniqueKey)).digest("hex");

	return hashedKey;
}

// This function takes the serial number and a unique key (password) from the IoT controller as an argument
// /requestNewToken?serial={serial}&key={unique_key}
//
// The unique key is generated through the IoT controller by the project group
//
// It does the following:
// 1. Validate that the serial and key match
// 2. Check if we have an existing database entry for this serial number
//    If false: Create a new user and assign user.token.serial
// 3. Return the user token to the IoT controller
export const requestNewToken = functions.region("europe-west1").https.onRequest(async (request, response) => {
	if(!request.query.serial || !request.query.key) {
		response.status(400).send("missing_parameter");
		return;
	}

	const serial = request.query.serial.toString();

	if(![...serial].every(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'))) {
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

	// iotDevice identifies this user as a smart garden (instead of a real person)
	const token = await getAuth().createCustomToken(serial, { iotDevice: true });
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
