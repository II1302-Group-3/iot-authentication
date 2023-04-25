import {PASSWORD, SIGNING_KEY} from "./secrets";

import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

import { createHmac } from "crypto";

admin.initializeApp();

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
export const requestNewToken = functions.region("europe-west1").https.onRequest((request, response) => {
	response.send("TODO");
});

// This function returns a unique key for a specific serial number if the user specifies the right password
// /signSerialNumber?serial={serial}&password={password}
export const signSerialNumber = functions.region("europe-west1").https.onRequest((request, response) => {
	if(request.query.serial && request.query.password) {
		if(request.query.password === PASSWORD) {
			const uniqueKey = { serial: request.query.serial, signingKey: SIGNING_KEY };
			const hashedKey = createHmac("sha256", JSON.stringify(uniqueKey)).digest("hex");

			response.send(hashedKey);
		}
		else {
			response.send("wrong_password");
		}
	}
	else {
		response.send("missing_parameter");
	}
});
