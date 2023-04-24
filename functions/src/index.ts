import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

admin.initializeApp();

// This function takes the serial number of the IoT controller as an argument (/requestNewToken/{serial})
//
// It does the following:
// 1. Check if we have an existing database entry for this serial number
// 2. If true: Reject the request
//    If false: Create a new user
// 3. Attach the serial number to the user token
// 4. Return the user token to the IoT controller
export const requestNewToken = functions.region("europe-west1").https.onRequest((request, response) => {
	const serial = request.query.text;
	response.send(serial);
});
