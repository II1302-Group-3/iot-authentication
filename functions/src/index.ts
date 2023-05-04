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
// Error codes: missing_parameter, invalid_serial, wrong_key
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
		const lastTokenTime = garden.child("last_token_time").val();
		const tokenTimeLeft = Math.floor(lastTokenTime + 45 * 60 - timestamp());

		// Token last for one hour, so create a new one if at least 45 minutes have passed
		if(tokenTimeLeft > 0) {
			response.send(`${garden.child("last_token").val()}:${tokenTimeLeft}:cached`);
			return;
		}
	}

	const auth = getAuth();
	const generatedTime = timestamp();
	// iotDevice identifies this user as a smart garden (instead of a real person)
	const token = await auth.createCustomToken(`garden_${serial}`, { iotDevice: true });

	await db.ref(`garden/${serial}/last_token_time`).set(generatedTime);
	await db.ref(`garden/${serial}/last_token`).set(token);

	const tokenTimeLeft = Math.floor(generatedTime + 45 * 60 - timestamp());
	response.send(`${token}:${tokenTimeLeft}:new`);
});

// This function returns a unique key for a specific serial number if the user specifies the right password
// Error codes: missing_parameter, wrong_password
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

// This function is called by the app when a user wants to add a new garden to their collection
// Error codes: missing_parameter, invalid_token, invalid_serial, garden_nickname_conflict, garden_offline, garden_already_claimed, too_many_gardens
// /addGarden?token={id_token}&serial={garden_serial}&nickname={garden_nickname}
export const addGarden = functions.region("europe-west1").https.onRequest(async (request, response) => {
	if(!request.query.token || !request.query.serial || !request.query.nickname) {
		response.status(400).send("missing_parameter");
		return;
	}

	request.query.serial = request.query.serial.toString().trim();
	request.query.nickname = request.query.nickname.toString().trim();

	const auth = getAuth();
	const db = getDatabase();

	try {
		const idToken = await auth.verifyIdToken(request.query.token.toString());
		const uid = idToken.uid;
		const claimedGardens = idToken.claimedGardens as string[];

		// User has claimed too many gardens
		if(claimedGardens && claimedGardens.length && claimedGardens.length > 10) {
			response.status(403).send("too_many_gardens");
			return;
		}

		for(const serial of claimedGardens ?? []) {
			const gardenNickname = (await db.ref(`garden/${serial}/nickname`).get()).val();

			if(gardenNickname === request.query.nickname) {
				response.status(403).send("garden_nickname_conflict");
				return;
			}
		}

		const garden = await db.ref(`garden/${request.query.serial}`).get();

		if(!garden.exists()) {
			response.status(404).send("invalid_serial");
			return;
		}

		const lastSyncTimeRef = garden.child("last_sync_time");

		// If the garden hasn't synced any values in the last five minutes
		if(!lastSyncTimeRef.exists() || timestamp() - lastSyncTimeRef.val() > 60 * 5) {
			functions.logger.warn(
				`User ${uid} tried to claim an offline garden ${request.query.serial}\n
				This is only allowed during the testing phase`
			);
		}

		const claimedByRef = garden.child("claimed_by");
		const isClaimedByOtherAccount = claimedByRef.exists() && claimedByRef.val() != uid;

		// If the garden is claimed by someone else
		if(isClaimedByOtherAccount) {
			response.status(403).send("garden_already_claimed");
			return;
		}

		await db.ref(`garden/${request.query.serial}/claimed_by`).set(uid);
		await db.ref(`garden/${request.query.serial}/nickname`).set(request.query.nickname.toString());

		const claimedGardensWithoutCurrent = claimedGardens ? [...claimedGardens].filter(g => g === request.query.serial) : [];
		await auth.setCustomUserClaims(uid, { claimedGardens: [...claimedGardensWithoutCurrent, request.query.serial] })

		response.send("success");
	}
	catch {
		response.status(400).send("invalid_token");
	}
});

// This function is called by the app when a user wants to remove a garden from their collection
// Error codes: missing_parameter, invalid_token, invalid_serial, garden_not_claimed
// /removeGarden?token={id_token}&serial={garden_serial}
export const removeGarden = functions.region("europe-west1").https.onRequest(async (request, response) => {
	if(!request.query.token || !request.query.serial) {
		response.status(400).send("missing_parameter");
		return;
	}

	request.query.serial = request.query.serial.toString().trim();

	const auth = getAuth();
	const db = getDatabase();

	try {
		const idToken = await auth.verifyIdToken(request.query.token.toString());
		const uid = idToken.uid;
		const claimedGardens = idToken.claimedGardens as string[];
		const garden = await db.ref(`garden/${request.query.serial}`).get();

		if(!garden.exists()) {
			response.status(404).send("invalid_serial");
			return;
		}

		const claimedByRef = garden.child("claimed_by");

		// The user could have the garden in their custom claims - always clean it up
		const claimedGardensWithoutCurrent = claimedGardens ? [...claimedGardens].filter(g => g === request.query.serial) : [];
		await auth.setCustomUserClaims(uid, { claimedGardens: claimedGardensWithoutCurrent })

		// If the garden is not claimed by you
		if(!claimedByRef.exists() || claimedByRef.val() != uid) {
			response.status(403).send("garden_not_claimed");
			return;
		}

		await db.ref(`garden/${request.query.serial}/claimed_by`).remove();
		await db.ref(`garden/${request.query.serial}/nickname`).remove();

		response.send("success");
	}
	catch {
		response.status(400).send("invalid_token");
	}
});
