// source: https://blog.logrocket.com/implementing-two-factor-authentication-using-speakeasy/

// connect with the required modules for the 2FA API
const express = require("express"); // Node.js web application server framework
const bodyParser = require('body-parser'); // middleware that parses the JSON, buffer, string, and URL encoded data of incoming HTTP POST requests and exposes them as req.body before they reach handlers
const speakeasy = require("speakeasy"); // secret and OTP token validator for two-factor authentication
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args)); // by default node doesn't have fetch, which we use for requests to the api that communicates with the main database

const app = express(); // creates an express application

// SET CORS
app.use(function(req, res, next) {
	res.header("Access-Control-Allow-Origin", "http://localhost:4200");
 	res.header("Access-Control-Allow-Methods", "OPTIONS,POST");
 	res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
	next();
});

// SET API PARSE
app.use(bodyParser.json()); // set JSON parser, all requests will use this
app.use(bodyParser.urlencoded({ extended: true })); // set URL-encoded parser, all requests will use this

// SET LISTENER
const port = 9000; // listen on port 9000 for connections
app.listen(port, () => { // bind and listen the connections on the specified host (localhost) and port (9000)
	console.log(`App is running on PORT: ${port}.`); // log host and port that is being listened on
});

// CREATE TEMPORARY SECRET
app.post("/api/register", (req, res) => { // listen on /api/register route for POST request
	console.log(req.body);

	const {email} = req.body; // obtain email from request body

	try { //  try...catch block to catch errors in the asynchronous code and pass them to Express
		fetch("http://localhost:5000/auth/get/bool", { // check whether user in question already has a permanent secret
			method: "POST", // we're sending sensitive data, so we're using the POST method with a body
			headers: {
				'Accept': 'application/json', // we only accept JSON data as response
				'Content-Type': 'application/json' // we're sending JSON data
			},
			body: JSON.stringify({email}) // the body containing the data to send to the API
		})
		.then(res => res.json()) // on success extract the JSON body content from the response object
		.then(data => { // block containing what we wanna do with the JSON data	
			console.log("Check for key...");
			if (data == true) { // if permanent secret exists
				console.log("Has existing permanent secret");
				res.json(data) // return that permanent secret already exists as JSON
			}
			else { // if permanent secret does not exist
				const temp_secret = speakeasy.generateSecret().base32; // create fresh Base32 temporary secret

				console.log("Generated new temporary secret: " + temp_secret);
				res.json({ email, secret: temp_secret}) // return fresh temporary secret as JSON
			}
		})
		.catch(function(res){ // on failure
			console.log("Failure: " + res)
		})
	}
	catch(error) { //  try...catch block to catch errors in the asynchronous code and pass them to Express
		console.error(error); // log error
		res.status(500).json({ message: 'Error generating secret key'}) // message to be logged alongside error
	}
})

// VERIFY TEMPORARY SECRET THROUGH ONE TIME PASSWORD TOKEN
app.post("/api/verify", (req,res) => { // listen on /api/verify route for POST request
	const { email, secret, token } = req.body; // obtain email, secret, and OTP from POST request and store them in variables
	console.log(req.body);

	try {
		const verified = speakeasy.totp.verify({ // verify the user by checking the OTP token against the temporary secret
			secret: secret, // the temporary secret
			encoding: 'base32', // the encoding of the temporary secret
			token: token // the one time password token
		});

		console.log(verified);

		if (verified) { // if verified is true
			fetch("http://localhost:5000/auth", { // send secret to database api to be stored in database
				method: "POST", // we're sending sensitive data, so we're using the POST method with a body
				headers: {
					'Accept': 'application/json', // we only accept JSON data as response
					'Content-Type': 'application/json' // we're sending JSON data
				},
				body: JSON.stringify({email, secret}) // the body containing the data to send to the API
			})
			.then(res => res.json()) // on success extract the JSON body content from the response object
			.then(data => { // block containing what we wanna do with the JSON data	
				console.log(data);
				if (data) {
					res.json({ verified: true})
				}
			})
			.catch(function(res){ // on failure
				console.log("Failure: " + res)
			})
		}
		else { // if verified is false
			res.json({ verified: false})
		}
	}
	catch(error) {
		console.error(error);
		res.status(500).json({ message: 'Error retrieving user'})
	};
})

// VALIDATION OF PERMANENT SECRET THROUGH ONE TIME PASSWORD TOKEN
app.post("/api/validate", (req,res) => { // listen on /api/validate route for POST request
	const { email, token } = req.body;
	console.log(req.body);

	try {
		fetch("http://localhost:5000/auth/get", { // send secret to database api to be stored in database
			method: "POST", // we're sending sensitive data, so we're using the POST method with a body
			headers: {
				'Accept': 'application/json', // we only accept JSON data as response
				'Content-Type': 'application/json' // we're sending JSON data
			},
			body: JSON.stringify({email}) // the body containing the data to send to the API
		})
		.then(res => res.json()) // on success extract the JSON body content from the response object
		.then(data => { // block containing what we wanna do with the JSON data	
			console.log(data);

			const validated = speakeasy.totp.verify({ // returns true if the one time password token matches
				secret: data.secret,
				encoding: 'base32',
				token: token
			});

			if (validated) {
				res.json({ validated: true })
			}
			else {
				res.json({ validated: false})
			}
		})
		.catch(function(res){ // on failure
			console.log("Failure: " + res)
		})
	}
	catch(error) {
		console.error(error);
		res.status(500).json({ message: 'Error retrieving user'})
	};
})