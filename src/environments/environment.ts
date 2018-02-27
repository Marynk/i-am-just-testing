// The file contents for the current environment will overwrite these during build.
// The build system defaults to the dev environment which uses `environment.ts`, but if you do
// `ng build --env=prod` then `environment.prod.ts` will be used instead.
// The list of which env maps to which file can be found in `.angular-cli.json`.

export const environment = {
  production: false,
  firebase: {
    apiKey: "AIzaSyBIYwaDygX1ivY1bAafSjDZO-g8lo6nqOM",
    authDomain: "i-am-just-testing.firebaseapp.com",
    databaseURL: "https://i-am-just-testing.firebaseio.com",
    projectId: "i-am-just-testing",
    storageBucket: "i-am-just-testing.appspot.com",
    messagingSenderId: "754483327691"
  }
};
