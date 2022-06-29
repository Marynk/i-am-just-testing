//Remote Memory Exposure
function name30(n) {
  if (n === '.') return 1
  return Buffer.byteLength(n) + 2
}

//Open Redirect
function trailingSlash () {
    var args = Array.prototype.slice.call(arguments)
    var done = middleware ? args.slice(-1)[0] : next

    var req = args[0]
    var res = args[1]
    var url = u.parse(req.url)
    var length = url.pathname.length
    var hasSlash = url.pathname.charAt(length - 1) === '/'

    if (hasSlash === slash) {
      if (middleware) {
        return done()
      }
      return next.apply(null, args)
    }

    if (slash) {
      url.pathname = url.pathname + '/'
    } else {
      url.pathname = url.pathname.slice(0, -1)
    }

    res.statusCode = status;
    res.setHeader('Location', u.format(url));
    const emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/

  return emailExpression.test(string)
    res.end();
  }

//Cross-site Scripting (XSS)
function htmlEncode(text) {
  return document.createElement('a').appendChild( document.createTextNode(text) ).parentNode.innerHTML;
}

//Regular Expression Denial of Service (ReDoS)
svg => {
	const entityRegex = /\s*<!Entity\s+\S*\s*(?:"|')[^"]+(?:"|')\s*>/img;
	// Remove entities
	return svg.replace(entityRegex, '');
}

//Regular Expression Denial of Service (ReDoS)
svg => svg.replace(/\[?(?:\s*<![A-Z]+[^>]*>\s*)*\]?/g, '')

//Prototype Pollution
function name1 (name) {
    return [this.aliasable('container.lookup'), '(depths, "', name, '")'];
  }

//Regular Expression Denial of Service (ReDoS)
function name2 (context, from, to) {
      var nodeVersions = jsReleases.filter(function (i) {
        return i.name === 'nodejs'
      }).map(function (i) {
        return i.version
      })
      var semverRegExp = /^(0|[1-9]\d*)(\.(0|[1-9]\d*)){0,2}$/
      if (!semverRegExp.test(from)) {
        throw new BrowserslistError(
          'Unknown version ' + from + ' of Node.js')
      }
      if (!semverRegExp.test(to)) {
        throw new BrowserslistError(
          'Unknown version ' + to + ' of Node.js')
      }
      return nodeVersions
        .filter(semverFilterLoose('>=', from))
        .filter(semverFilterLoose('<=', to))
        .map(function (v) {
          return 'node ' + v
        })
    }

//Regular Expression Denial of Service (ReDoS)
function getAnnotationURL(sourceMapString) {
    return sourceMapString.match(/\/\*\s*# sourceMappingURL=(.*)\*\//)[1].trim()
  }

//Regular Expression Denial of Service (ReDoS)
function loadAnnotation(css) {
    let annotations = css.match(/\/\*\s*# sourceMappingURL=.*\*\//gm)

    if (annotations && annotations.length > 0) {
      // Locate the last sourceMappingURL to avoid picking up
      // sourceMappingURLs from comments, strings, etc.
      let lastAnnotation = annotations[annotations.length - 1]
      if (lastAnnotation) {
        this.annotation = this.getAnnotationURL(lastAnnotation)
      }
    }
  }

//Information Exposure
function name3 (bind) {
    bindContributionProvider(bind, ConnectionContainerModule);
    bindContributionProvider(bind, MessagingService.Contribution);
    bind(MessagingContribution).toDynamicValue(({ container }) => {
        const child = container.createChild();
        child.bind(MessagingContainer).toConstantValue(container);
        child.bind(MessagingContribution).toSelf();
        return child.get(MessagingContribution);
    }).inSingletonScope();
    bind(BackendApplicationContribution).toService(MessagingContribution);
}

//Regular Expression Denial of Service (ReDoS)
function getAnnotationURL1(sourceMapString) {
    return sourceMapString
      .match(/\/\*\s*# sourceMappingURL=(.*)\s*\*\//)[1]
      .trim()
  }

//Prototype Pollution
function set  (object, path, val, obj) {
  return !/__proto__/.test(path) && ((path = path.split ? path.split('.') : path.slice(0)).slice(0, -1).reduce(function (obj, p) {
    return obj[p] = obj[p] || {};
  }, obj = object)[path.pop()] = val), object;
}

//Prototype Pollution
function extend(...args) {
  const to = Object(args[0]);
  for (let i = 1; i < args.length; i += 1) {
    const nextSource = args[i];
    if (nextSource !== undefined && nextSource !== null) {
      const keysArray = Object.keys(Object(nextSource));
      for (let nextIndex = 0, len = keysArray.length; nextIndex < len; nextIndex += 1) {
        const nextKey = keysArray[nextIndex];
        const desc = Object.getOwnPropertyDescriptor(nextSource, nextKey);
        if (desc !== undefined && desc.enumerable) {
          if (isObject(to[nextKey]) && isObject(nextSource[nextKey])) {
            extend(to[nextKey], nextSource[nextKey]);
          } else if (!isObject(to[nextKey]) && isObject(nextSource[nextKey])) {
            to[nextKey] = {};
            extend(to[nextKey], nextSource[nextKey]);
          } else {
            to[nextKey] = nextSource[nextKey];
          }
        }
      }
    }
  }
  return to;
}

//Regular Expression Denial of Service (ReDoS)
function normalizeSpacing( htmlString ) {
	// Run normalizeSafariSpaceSpans() two times to cover nested spans.
	return normalizeSafariSpaceSpans( normalizeSafariSpaceSpans( htmlString ) )
		// Remove all \r\n from "spacerun spans" so the last replace line doesn't strip all whitespaces.
		.replace( /(<span\s+style=['"]mso-spacerun:yes['"]>[\s]*?)[\r\n]+(\s*<\/span>)/g, '$1$2' )
		.replace( /<span\s+style=['"]mso-spacerun:yes['"]><\/span>/g, '' )
		.replace( / <\//g, '\u00A0</' )
		.replace( / <o:p><\/o:p>/g, '\u00A0<o:p></o:p>' )
		// Remove <o:p> block filler from empty paragraph. Safari uses \u00A0 instead of &nbsp;.
		.replace( /<o:p>(&nbsp;|\u00A0)<\/o:p>/g, '' )
		// Remove all whitespaces when they contain any \r or \n.
		.replace( />(\s*[\r\n]\s*)</g, '><' );
}

//Regular Expression Denial of Service (ReDoS)
function cleanListItem( evt, data, conversionApi ) {
	if ( conversionApi.consumable.test( data.viewItem, { name: true } ) ) {
		if ( data.viewItem.childCount === 0 ) {
			return;
		}

		const children = [ ...data.viewItem.getChildren() ];

		let foundList = false;
		let firstNode = true;

		for ( const child of children ) {
			if ( foundList && !isList( child ) ) {
				child._remove();
			}

			if ( child.is( '$text' ) ) {
				// If this is the first node and it's a text node, left-trim it.
				if ( firstNode ) {
					child._data = child.data.replace( /^\s+/, '' );
				}

				// If this is the last text node before <ul> or <ol>, right-trim it.
				if ( !child.nextSibling || isList( child.nextSibling ) ) {
					child._data = child.data.replace( /\s+$/, '' );
				}
			} else if ( isList( child ) ) {
				// If this is a <ul> or <ol>, do not process it, just mark that we already visited list element.
				foundList = true;
			}

			firstNode = false;
		}
	}
}

//Arbitrary Command Injection
async port => {
	try {
		const result = (await exec(`lsof -i :${port}`)).output.split('\n');
		const headers = result.shift().split(' ').filter(item => !!item.trim() && item.trim() !== "").map(item => item.toLowerCase());
		return result.filter(item => !!item.trim() && item.trim() !== "").reduce((accumulator, currentValue) => {
			accumulator.push(currentValue.split(' ').filter(item => !!item.trim() && item.trim() !== "").reduce((accumulator, currentValue, index) => {
				if (index > headers.length - 1) {
					accumulator[headers[headers.length - 1]] = (!!accumulator[headers[headers.length - 1]].trim() && accumulator[headers[headers.length - 1]].trim() !== "") ? `${accumulator[headers[headers.length - 1]]} ${currentValue}` : currentValue;
				} else {
					accumulator[headers[index]] = currentValue;
				}
				return accumulator;
			}, {}));
			return accumulator;
		}, []);
	} catch (e) {
		console.error(e);
	}
}

//Arbitrary Command Injection
function name4 (port) {
  var processId = null
  try {
    processId = exec(`lsof -t -i:${port}`)
  } catch (e) {

  }

  if (processId !== null) { // if exists kill
    exec(`kill ${processId}`)
  }
}

//Arbitrary Code Execution
function escapeShellArg(arg) {
  return arg.replace(/'/g, `'\\''`);
}

//Arbitrary Code Execution
function escapeShellArg1(arg) {
  return arg.replace(/"/g, `""`);
}

//Prototype Pollution
function decodeMap (buf, offset, length, headerLength) {
    var result = {}
    var key
    var i
    var totalBytesConsumed = 0

    offset += headerLength
    for (i = 0; i < length; i++) {
      var keyResult = tryDecode(buf, offset)
      if (keyResult) {
        offset += keyResult.bytesConsumed
        var valueResult = tryDecode(buf, offset)
        if (valueResult) {
          key = keyResult.value
          result[key] = valueResult.value
          offset += valueResult.bytesConsumed
          totalBytesConsumed += (keyResult.bytesConsumed + valueResult.bytesConsumed)
        } else {
          return null
        }
      } else {
        return null
      }
    }
    return buildDecodeResult(result, headerLength + totalBytesConsumed)
  }

//Regular Expression Denial of Service (ReDoS)
function name5 (string) {
	if (!string) {
		return null;
	}

	var hsl = /^hsla?\(\s*([+-]?(?:\d*\.)?\d+)(?:deg)?\s*,\s*([+-]?[\d\.]+)%\s*,\s*([+-]?[\d\.]+)%\s*(?:,\s*([+-]?[\d\.]+)\s*)?\)$/;
	var match = string.match(hsl);

	if (match) {
		var alpha = parseFloat(match[4]);
		var h = (parseFloat(match[1]) + 360) % 360;
		var s = clamp(parseFloat(match[2]), 0, 100);
		var l = clamp(parseFloat(match[3]), 0, 100);
		var a = clamp(isNaN(alpha) ? 1 : alpha, 0, 1);

		return [h, s, l, a];
	}

	return null;
}

//Regular Expression Denial of Service (ReDoS)
function name6 (string) {
	if (!string) {
		return null;
	}

	var hwb = /^hwb\(\s*([+-]?\d*[\.]?\d+)(?:deg)?\s*,\s*([+-]?[\d\.]+)%\s*,\s*([+-]?[\d\.]+)%\s*(?:,\s*([+-]?[\d\.]+)\s*)?\)$/;
	var match = string.match(hwb);

	if (match) {
		var alpha = parseFloat(match[4]);
		var h = ((parseFloat(match[1]) % 360) + 360) % 360;
		var w = clamp(parseFloat(match[2]), 0, 100);
		var b = clamp(parseFloat(match[3]), 0, 100);
		var a = clamp(isNaN(alpha) ? 1 : alpha, 0, 1);
		return [h, w, b, a];
	}

	return null;
}

//Regular Expression Denial of Service (ReDoS)
function name7 (
    dataUrl
  ) {
    dataUrl = dataUrl || "";
    var dataUrlParts = dataUrl.split("base64,");
    var result = null;

    if (dataUrlParts.length === 2) {
      var extractedInfo = /^data:(\w*\/\w*);*(charset=[\w=-]*)*;*$/.exec(
        dataUrlParts[0]
      );
      if (Array.isArray(extractedInfo)) {
        result = {
          mimeType: extractedInfo[1],
          charset: extractedInfo[2],
          data: dataUrlParts[1]
        };
      }
    }
    return result;
  }

//Command Injection
function checkGraphvizInstalled(config) {
	if (config.graphVizPath) {
		const cmd = path.join(config.graphVizPath, 'gvpr -V');
		return exec(cmd)
			.catch(() => {
				throw new Error('Could not execute ' + cmd);
			});
	}

	return exec('gvpr -V')
		.catch((error) => {
			throw new Error('Graphviz could not be found. Ensure that "gvpr" is in your $PATH.\n' + error);
		});
}

//Open Redirect
function getRedirectUrl(query) {
    try {
        const redirect = decodeURIComponent(query.r || '/');
        return url.parse(redirect).pathname;
    } catch (e) {
        return '/';
    }
}

//Sandbox Bypass
function name8 (e) {
    if (e.origin === lockOrigin) {
        if (e.data.blob) remoteRender(e);
        else remoteSetTint(e);
    }
}

//Directory Traversal
function loadProject(name) {
    var projectPath = name;
    if (projectPath.indexOf(fspath.sep) === -1) {
        projectPath = fspath.join(projectsDir,name);
    }
    return Projects.load(projectPath).then(function(project) {
        activeProject = project;
        flowsFullPath = project.getFlowFile();
        flowsFileBackup = project.getFlowFileBackup();
        credentialsFile = project.getCredentialsFile();
        credentialsFileBackup = project.getCredentialsFileBackup();
        return project;
    })
}

//Directory Traversal
function deleteProject(user, name) {
    if (activeProject && activeProject.name === name) {
        var e = new Error("NLS: Can't delete the active project");
        e.code = "cannot_delete_active_project";
        throw e;
    }
    var projectPath = fspath.join(projectsDir,name);
    return Projects.delete(user, projectPath);
}

//Prototype Pollution
function _recursiveMerge(base, extend) {
    if (!isPlainObject(base))
        return extend;
    for (var key in extend)
        base[key] = (isPlainObject(base[key]) && isPlainObject(extend[key])) ?
            _recursiveMerge(base[key], extend[key]) :
            extend[key];
    return base;
}

//Improper Input Validation
function extractProtocol(address) {
  address = trimLeft(address);
  var match = protocolre.exec(address);

  return {
    protocol: match[1] ? match[1].toLowerCase() : '',
    slashes: !!match[2],
    rest: match[3]
  };
}

//Cross-site Scripting (XSS)
function isExternal(url) {
  let match = url.match(
    /^([^:/?#]+:)?(?:\/\/([^/?#]*))?([^?#]+)?(\?[^#]*)?(#.*)?/
  );
  if (
    typeof match[1] === 'string' &&
    match[1].length > 0 &&
    match[1].toLowerCase() !== location.protocol
  ) {
    return true;
  }
  if (
    typeof match[2] === 'string' &&
    match[2].length > 0 &&
    match[2].replace(
      new RegExp(
        ':(' + { 'http:': 80, 'https:': 443 }[location.protocol] + ')?$'
      ),
      ''
    ) !== location.host
  ) {
    return true;
  }
  return false;
}

//Prototype Pollution
function getLastOfPath(object, path, Empty) {
    function cleanKey(key) {
      return key && key.indexOf('###') > -1 ? key.replace(/###/g, '.') : key;
    }

    function canNotTraverseDeeper() {
      return !object || typeof object === 'string';
    }

    var stack = typeof path !== 'string' ? [].concat(path) : path.split('.');

    while (stack.length > 1) {
      if (canNotTraverseDeeper()) return {};
      var key = cleanKey(stack.shift());
      if (!object[key] && Empty) object[key] = new Empty();
      object = object[key];
    }

    if (canNotTraverseDeeper()) return {};
    return {
      obj: object,
      k: cleanKey(stack.shift())
    };
  }

//Prototype Pollution
function getLastOfPath1(object, path, Empty) {
  function cleanKey(key) {
    return key && key.indexOf('###') > -1 ? key.replace(/###/g, '.') : key;
  }

  function canNotTraverseDeeper() {
    return !object || typeof object === 'string';
  }

  const stack = typeof path !== 'string' ? [].concat(path) : path.split('.');
  while (stack.length > 1) {
    if (canNotTraverseDeeper()) return {};

    const key = cleanKey(stack.shift());
    if (!object[key] && Empty) object[key] = new Empty();
    object = object[key];
  }

  if (canNotTraverseDeeper()) return {};
  return {
    obj: object,
    k: cleanKey(stack.shift()),
  };
}

//Directory Traversal
function name9 (child) {
					if (child.isDirectory) return;
					var content = child.getData();
					if (!content) {
						throw new Error(Utils.Errors.CANT_EXTRACT_FILE);
					}
					var childName = sanitize(targetPath, maintainEntryPath ? child.entryName : pth.basename(child.entryName));

					Utils.writeFileTo(childName, content, overwrite);
				}

//Remote Code Execution (RCE)
function name10 (obj, name, loc) {
      if (!obj || !(name in obj)) {
        throw new Exception('"' + name + '" not defined in ' + obj, {
          loc: loc
        });
      }
      return obj[name];
    }

//Directory Traversal
function constructor(connection, {root, cwd} = {}) {
    this.connection = connection;
    this.cwd = nodePath.normalize(cwd ? nodePath.join(nodePath.sep, cwd) : nodePath.sep);
    this._root = nodePath.resolve(root || process.cwd());
  }

//Command Injection
function execute(cmd, cmdArgs, workingDir) {
    const fullCmd = wrap(util.format("%s %s", cmd, cmdArgs));
    const command = [
      "smbclient",
      this.getSmbClientArgs(fullCmd).join(" "),
    ].join(" ");

    const options = {
      cwd: workingDir || "",
    };
    const maskCmd = this.maskCmd;

    return new Promise((resolve, reject) => {
      exec(command, options, function (err, stdout, stderr) {
        const allOutput = stdout + stderr;

        if (err) {
          // The error message by default contains the whole smbclient command that was run
          // This contains the username, password in plain text which can be a security risk
          // maskCmd option allows user to hide the command from the error message
          err.message = maskCmd ? allOutput : err.message + allOutput;
          return reject(err);
        }

        return resolve(allOutput);
      });
    });
  }

//Command Injection
function getAllShares() {
    const maskCmd = this.maskCmd;
    return new Promise((resolve, reject) => {
      exec("smbtree -U guest -N", {}, function (err, stdout, stderr) {
        const allOutput = stdout + stderr;

        if (err !== null) {
          err.message = maskCmd ? allOutput : err.message + allOutput;
          return reject(err);
        }

        const shares = [];
        for (const line in stdout.split(/\r?\n/)) {
          const words = line.split(/\t/);
          if (words.length > 2 && words[2].match(/^\s*$/) !== null) {
            shares.append(words[2].trim());
          }
        }

        return resolve(shares);
      });
    });
  }

//Prototype Pollution
function merge(target, obj) {
  for (var key in obj) {
    if (key === '__proto__' || !hasOwn(obj, key)) {
      continue;
    }

    var oldVal = obj[key];
    var newVal = target[key];

    if (isObject(newVal) && isObject(oldVal)) {
      target[key] = merge(newVal, oldVal);
    } else if (Array.isArray(newVal)) {
      target[key] = union([], newVal, oldVal);
    } else {
      target[key] = clone(oldVal);
    }
  }
  return target;
}

//Prototype Pollution
function put(object, path, value) {
  if (typeof path === "string") {
    path = path.split(".");
  }

  if (!(path instanceof Array) || path.length === 0) {
    return false;
  }
  
  path = path.slice();

  var key = path.shift();

  if (typeof object !== "object" || object === null) {
    return false;
  }

  if (path.length === 0) {
    object[key] = value;
  } else {
    if (typeof object[key] === "undefined") {
      object[key] = {};
    }

    if (typeof object[key] !== "object" || object[key] === null) {
      return false;
    }

    return put(object[key], path, value);
  }
}

//Cross-site Scripting (XSS)
function toast (message, type = 'normal') {
  const src = `(function() {
    __VUE_DEVTOOLS_TOAST__(\`${message}\`, '${type}');
  })()`

  chrome.devtools.inspectedWindow.eval(src, function (res, err) {
    if (err) {
      console.log(err)
    }
  })
}

//Arbitrary Code Execution
function name11 (str) {
        return new(tree.Anonymous)(str instanceof tree.JavaScript ? str.evaluated : str);
    }

//Arbitrary Code Execution
function name12 (_, exp) {
            return new(tree.JavaScript)(exp, that.index, true).eval(env).value;
        }

//Open Redirect
function getRedirectUrl1(query) {
    try {
        const redirect = decodeURIComponent(query.r || '/');
        return url.parse(redirect).pathname;
    } catch (e) {
        return '/';
    }
}

//Command Injection
function name13 (type, writer) {

	var self = this;

	!self.builder.length && self.minify();

	if (!type)
		type = self.outputType;

	F.stats.performance.open++;
	var cmd = spawn(CMD_CONVERT[self.cmdarg], self.arg(self.filename ? wrap(self.filename) : '-', (type ? type + ':' : '') + '-'), SPAWN_OPT);
	if (self.currentStream) {
		if (self.currentStream instanceof Buffer)
			cmd.stdin.end(self.currentStream);
		else
			self.currentStream.pipe(cmd.stdin);
	}

	writer && writer(cmd.stdin);
	var middleware = middlewares[type];
	return middleware ? cmd.stdout.pipe(middleware()) : cmd.stdout;
}

//Remote Code Execution (RCE)
function cmdSet(key, val) {
  var objVal = val;

  try {
    var strTest = /^[\'\"](.*?)[\'\"]$/.exec(val);
    if (!strTest || strTest.length !== 2) { // do not parse if explicitly a string
      objVal = eval('(' + val + ')'); // attempt to parse
    } else {
      objVal = strTest[1];
    }
  } catch(ex) {
    // use as existing string
  }

  instance.setProp(key, objVal);
  rl.write(': stored as type ' + typeof objVal);

  enterCommand();
}

//Command Injection
async function name14 (destination, { hard = true } = {}) {
	if (destination && typeof destination === 'string') {
		return await exec(`git reset ${JSON.stringify(destination)} ${hard ? '--hard' : ''}`);
	}

	if (destination && typeof destination === 'number') {
		return await exec(`git reset HEAD~${Math.abs(destination)} ${hard ? '--hard' : ''}`);
	}

	throw new TypeError(`No case for handling destination ${destination} (${typeof destination})`);
}

//Regular Expression Denial of Service (ReDoS)
function name15 ( value, element ) {

			// Copyright (c) 2010-2013 Diego Perini, MIT licensed
			// https://gist.github.com/dperini/729294
			// see also https://mathiasbynens.be/demo/url-regex
			// modified to allow protocol-relative URLs
			return this.optional( element ) || /^(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})).?)(?::\d{2,5})?(?:[/?#]\S*)?$/i.test( value );
		}

//Remote Code Execution (RCE)
function name16 (range) {
    if (!this.myDevice.connection) return new Promise((_, reject) => reject(new Error('No connection!')));
    if (!range) {
        range = this._getFullRange();
        if (!range.length) {
            return new Promise((_, reject) => reject(new Error('No connection!')));
        }
    }

    const pings = range.map(ip => new Promise((resolve, reject) => {
        exec(`ping ${flag} ${this.timeout} ${ip}`, (err, stdout) => {
            if (err || stdout.includes(`100% packet loss`)) return reject(ip);
            return resolve(ip);
        });
    }));
    return Promise.allSettled(pings)
        .then(results => results.reduce((ret, { status, value = null, reason: ip = null }) => {
            if (status === 'fulfilled') ret.hosts.push(value);
            else ret.missing.push(ip);
            return ret;
        }, { hosts: [], missing: [] }));
}

//Prototype Pollution
function name17 (key, value) {
   var parsedValue = ('' + value).trim();

   this._properties = this._propertyAppender(this._properties, key, parsedValue);

   var expanded = key.split('.');
   var source = this._propertiesExpanded;

   while (expanded.length > 1) {
      var step = expanded.shift();
      if (expanded.length >= 1 && typeof source[step] === 'string') {
         source[step] = {'': source[step]};
      }
      source = (source[step] = source[step] || {});
   }

   if (typeof parsedValue === 'string' && typeof  source[expanded[0]] === 'object') {
      source[expanded[0]][''] = parsedValue;
   }
   else {
      source[expanded[0]] = parsedValue;
   }

   return this;
}

//Denial of Service (DoS)
function nameconstructor(opts = {}) {
    // super();

    this.clients = {};
    this.clientsCount = 0;

    this.opts = Object.assign(
      {
        wsEngine: process.env.EIO_WS_ENGINE || "ws",
        pingTimeout: 5000,
        pingInterval: 25000,
        upgradeTimeout: 10000,
        maxHttpBufferSize: 10e7,
        transports: Object.keys(transports),
        allowUpgrades: true,
        perMessageDeflate: {
          threshold: 1024
        },
        httpCompression: {
          threshold: 1024
        },
        cors: false
      },
      opts
    );

    if (opts.cookie) {
      this.opts.cookie = Object.assign(
        {
          name: "io",
          path: "/",
          httpOnly: opts.cookie.path !== false,
          sameSite: "lax"
        },
        opts.cookie
      );
    }

    if (this.opts.cors) {
      this.corsMiddleware = require("cors")(this.opts.cors);
    }

    this.init();
  }

//Improper Input Validation
function name18 (string, parts) {
    // extract username:password
    var firstBackSlash = string.indexOf('\\');
    var firstSlash = string.indexOf('/');
    var slash = firstBackSlash === -1 ? firstSlash : (firstSlash !== -1 ? Math.min(firstBackSlash, firstSlash): firstSlash)
    var pos = string.lastIndexOf('@', firstSlash > -1 ? firstSlash : string.length - 1);
    var t;

    // authority@ must come before /path or \path
    if (pos > -1 && (slash === -1 || pos < slash)) {
      t = string.substring(0, pos).split(':');
      parts.username = t[0] ? URI.decode(t[0]) : null;
      t.shift();
      parts.password = t[0] ? URI.decode(t.join(':')) : null;
      string = string.substring(pos + 1);
    } else {
      parts.username = null;
      parts.password = null;
    }

    return string;
  }

//Prototype Pollution
function arrowFunc0(obj, arrKey, val, isAppend) {
  const last = arrKey.pop();
  arrKey.forEach((k) => {
    obj[k] = obj[k] || {};
    obj = obj[k];
  });
  if (isAppend && (!obj[last] || !obj[last].push)) {
    if (!obj[last]) {
      obj[last] = [val];
    } else {
      obj[last] = [obj[last], val];
    }
  } else if (isAppend && obj[last].push) {
    obj[last].push(val);
  } else {
    obj[last] = val;
  }
}

//Prototype Pollution
function set1  (object, path, val, obj) {
  return ((path = path.split ? path.split('.') : path.slice(0)).slice(0, -1).reduce(function (obj, p) {
    return obj[p] = obj[p] || {};
  }, obj = object)[path.pop()] = val), object;
}

//Prototype Pollution
function deepCopy(sourceObj, destinationObj) {
    var out = destinationObj || {};
    Object.keys(sourceObj).forEach(function (key) {
        if (typeof sourceObj[key] === 'object') {
            out[key] = (util.isArray(sourceObj[key]) ? [] : {});
            deepCopy(sourceObj[key], out[key]);
        } else {
            out[key] = sourceObj[key];
        }
    });

    return out;
}

//Regular Expression Denial of Service (ReDoS)
function converted() {
  return /(?<=^v?|\sv?)(?:(?:0|[1-9]\d*)\.){2}(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[\da-z-]*[a-z-][\da-z-]*)(?:\.(?:0|[1-9]\d*|[\da-z-]*[a-z-][\da-z-]*))*)?(?:\+[\da-z-]+(?:\.[\da-z-]+)*)?(?=$|\s)/gi;
}

//Regular Expression Denial of Service (ReDoS)
function name19 (formatString) {
        var re = /\[([^\[\]]*|\[[^\[\]]*\])*\]|([A-Za-z])\2+|\.{3}|./g, keys, pattern = [formatString];

        while ((keys = re.exec(formatString))) {
            pattern[pattern.length] = keys[0];
        }
        return pattern;
    }

//Cross-site Request Forgery (CSRF)
function name20 (params, callback) {
		var app = params.router,
			middleware = params.middleware,
			controllers = params.controllers;
			
		fs.readFile(path.resolve(__dirname, './public/templates/comments/comments.tpl'), function name31(err, data) {
			Comments.template = data.toString();
		});

		app.get('/comments/get/:id/:pagination?', middleware.applyCSRF, Comments.getCommentData);
		app.post('/comments/reply', Comments.replyToComment);
		app.post('/comments/publish', Comments.publishArticle);

		app.get('/admin/blog-comments', middleware.admin.buildHeader, renderAdmin);
		app.get('/api/admin/blog-comments', renderAdmin);

		callback();
	}

//Command Injection
function name21 (val) {
    args.push(escapeFn(val));
  }

//Cross-site Scripting (XSS)
function name32( color ) {
								if ( color ) {
									setColor( color, colorName, history );
								}
							}

//Regular Expression Denial of Service (ReDoS)
function name33(hljs) {
  const commentMode = hljs.COMMENT(/\(\*/, /\*\)/);

  const nonTerminalMode = {
    className: "attribute",
    begin: /^[ ]*[a-zA-Z][a-zA-Z_-]*([\s_-]+[a-zA-Z][a-zA-Z]*)*/
  };

  const specialSequenceMode = {
    className: "meta",
    begin: /\?.*\?/
  };

  const ruleBodyMode = {
    begin: /=/,
    end: /[.;]/,
    contains: [
      commentMode,
      specialSequenceMode,
      {
        // terminals
        className: 'string',
        variants: [
          hljs.APOS_STRING_MODE,
          hljs.QUOTE_STRING_MODE,
          {
            begin: '`',
            end: '`'
          }
        ]
      }
    ]
  };

  return {
    name: 'Extended Backus-Naur Form',
    illegal: /\S/,
    contains: [
      commentMode,
      nonTerminalMode,
      ruleBodyMode
    ]
  };
}

//Prototype Pollution
function setByPath(target, path, value) {
  path = pathToArray(path);

  if (! path.length) {
    return value;
  }

  const key = path[0];
  if (isNumber(key)) {
    if (! Array.isArray(target)) {
      target = [];
    }
  }
  else if (! isObject(target)) {
    target = {};
  }

  if (path.length > 1) {
    target[key] = setByPath(target[key], path.slice(1), value);
  }
  else {
    target[key] = value;
  }

  return target;
}

//Prototype Pollution
function at(target, path, update) {
  path = pathToArray(path);

  if (! path.length) {
    return update(target, null);
  }

  const key = path[0];
  if (isNumber(key)) {
    if (! Array.isArray(target)) {
      target = [];
    }
  }
  else if (! isObject(target)) {
    target = {};
  }

  if (path.length > 1) {
    target[key] = at(target[key], path.slice(1), update);
  }
  else {
    target = update(target, key);
  }

  return target;
}

//Prototype Pollution
function methodByPath(target, path) {
  path = pathToArray(path);

  const values = breadcrumbs(target, path);

  if (values.length < path.length) {
    return noop;
  }

  if (typeof values[values.length - 1] !== 'function') {
    return noop;
  }

  if (values.length > 1) {
    return values[values.length - 1].bind(values[values.length - 2]);
  }
  else {
    return values[0].bind(target);
  }
}

//Information Disclosure
function arrowFunc1(env) {
  const toReplace = Object.keys(env).filter((envVar) => {
    // https://github.com/semantic-release/semantic-release/issues/1558
    if (envVar === 'GOPRIVATE') {
      return false;
    }

    return /token|password|credential|secret|private/i.test(envVar) && size(env[envVar].trim()) >= SECRET_MIN_SIZE;
  });

  const regexp = new RegExp(toReplace.map((envVar) => escapeRegExp(env[envVar])).join('|'), 'g');
  return (output) =>
    output && isString(output) && toReplace.length > 0 ? output.toString().replace(regexp, SECRET_REPLACEMENT) : output;
}

//Regular Expression Denial of Service (ReDoS)
function name34(str) {
		str = str.replace(/^\s*|\s*$/g, '');
		str = str.replace(/^\t*|\t*$/g, '');
		return (/^\w+([\.\+-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(str));
	}

//Arbitrary File Read
function name35(request, networkRequest) {
    console.log('Request ' + request.url);
    if (request.url.lastIndexOf(body.url, 0) === 0) {
        return;
    }

    //potentially dangerous request
    if (request.url.lastIndexOf("file:///", 0) === 0 && !body.allowLocalFilesAccess) {
        networkRequest.abort();
        return;
    }

    //to support cdn like format //cdn.jquery...
    if (request.url.lastIndexOf("file://", 0) === 0 && request.url.lastIndexOf("file:///", 0) !== 0) {
        networkRequest.changeUrl(request.url.replace("file://", "http://"));
    }

    if (body.waitForJS && request.url.lastIndexOf("http://intruct-javascript-ending", 0) === 0) {
        pageJSisDone = true;
    }
}

//Prototype Pollution
function apply(doc, patch) {
  if (typeof patch !== OBJECT || patch === null || Array.isArray(patch)) {
    return patch;
  }

  if (typeof doc !== OBJECT || doc === null || Array.isArray(doc)) {
    doc = Object.create(null);
  }

  const keys = Object.keys(patch);
  for (const key of keys) {
    const v = patch[key];
    if (v === null) {
      delete doc[key];
      continue;
    }
    doc[key] = apply(doc[key], v);
  }

  return doc;
}

//Prototype Pollution
function _setNestedProperty(currentObject, currentProperty, segments, index) {
            if (!currentObject[currentProperty]) {
                const nextPropIsNumber = Number.isInteger(Number(segments[index + 1]));
                const nextPropIsArrayWildcard = segments[index + 1] === ARRAY_WILDCARD;

                if (nextPropIsNumber || nextPropIsArrayWildcard) {
                    currentObject[currentProperty] = [];
                } else {
                    currentObject[currentProperty] = {};
                }
            }

            if (isLastSegment(segments, index)) {
                currentObject[currentProperty] = value;
            }

            return currentObject[currentProperty];
        }

//Regular Expression Denial of Service (ReDoS)
function email (em) {
  if (!em.match(/^.+@.+\..+$/)) {
    return new Error(requirements.email.valid)
  }

  return null
}

//Prototype Pollution
function deepExtend (a, b) {
  // TODO: add support for Arrays to deepExtend
  if (Array.isArray(b)) {
    throw new TypeError('Arrays are not supported by deepExtend')
  }

  for (const prop in b) {
    if (hasOwnProperty(b, prop)) {
      if (b[prop] && b[prop].constructor === Object) {
        if (a[prop] === undefined) {
          a[prop] = {}
        }
        if (a[prop] && a[prop].constructor === Object) {
          deepExtend(a[prop], b[prop])
        } else {
          a[prop] = b[prop]
        }
      } else if (Array.isArray(b[prop])) {
        throw new TypeError('Arrays are not supported by deepExtend')
      } else {
        a[prop] = b[prop]
      }
    }
  }
  return a
}

//Prototype Pollution
function baseExtend(args, merge) {
  var i, j, obj, src, key, keys, len;
  var target = args[0];
  var length = args.length;

  for (i = 1; i < length; ++i) {

    obj = args[i];
    if ((obj === null || typeof obj !== 'object') && typeof obj !== 'function'){
      continue;
    }

    keys = Object.keys(obj);
    len = keys.length;

    for (j = 0; j < len; j++) {
      key = keys[j];
      src = obj[key];

      if (clonable(src)) {
        if (merge && clonable(target[key])) {
          baseExtend([target[key], src], merge);
        } else if (src !== undefined) {
          target[key] = baseExtend([{}, src], merge);
        }
      } else if (src !== undefined) {
        target[key] = Array.isArray(src) ? src.slice() : src;
      }
    }
  }
  return target;
}

//Command Injection
exitCode => {
      if (exitCode === 0) {
        resolve();
      } else {
        // exit code 12 means "nothing to do" right?
        //console.log('rejecting', zipProcess)
        reject(
          new Error(
            `Unexpected exit code from native zip command: ${exitCode}\n executed command '${command}'\n executed inin directory '${options.cwd ||
              process.cwd()}'`
          )
        );
      }
    }

//Command Injection
options =>
  new Promise((resolve, reject) => {
    const sources = Array.isArray(options.source)
      ? options.source.join(" ")
      : options.source;
    const command = `zip --quiet --recurse-paths ${
      options.destination
    } ${sources}`;
    const zipProcess = cp.exec(command, {
      stdio: "inherit",
      cwd: options.cwd
    });
    zipProcess.on("error", reject);
    zipProcess.on("close", exitCode => {
      if (exitCode === 0) {
        resolve();
      } else {
        // exit code 12 means "nothing to do" right?
        //console.log('rejecting', zipProcess)
        reject(
          new Error(
            `Unexpected exit code from native zip command: ${exitCode}\n executed command '${command}'\n executed inin directory '${options.cwd ||
              process.cwd()}'`
          )
        );
      }
    });
  })

//Prototype Pollution
function deepSet(parent, key, value, mode) {
    // if(typeof value==='string') value = value.replace(/(\r\n|\r|\n)\s*$/, ''); // replace line endings and white spaces
    var parts = key.split('.');
    var current = parent;
    if(key==='this') {
        if(mode==='push') parent.push(value);
        else parent = value.toString();
    }
    else {
        for(var i=0; i<parts.length; i++) {
            if(i >= parts.length-1) {
                if(mode==='push') current[parts[i]].push(value);
                else current[parts[i]] = value;
            }
            else current[parts[i]] = current[parts[i]] || {};    
            current = current[parts[i]];
        }
    }
    return parent;
}

//Remote Memory Exposure
function consume (bytes) {
  while (this._bufs.length) {
    if (bytes >= this._bufs[0].length) {
      bytes -= this._bufs[0].length
      this.length -= this._bufs[0].length
      this._bufs.shift()
    } else {
      this._bufs[0] = this._bufs[0].slice(bytes)
      this.length -= bytes
      break
    }
  }
  return this
}

//Remote Code Execution (RCE)
function launch (opts, cb) {
  opts = Object.assign({ poll: true, pollInterval: 3000 }, opts);
  exec('start microsoft-edge:' + opts.uri, (err, stdout, stderr) => {
    if (err) return cb(err);
    const ee = new EventEmitter();

    // fake returning a child_process object
    ee.kill = kill.bind(null, ee);

    // Polls for the external termination of Edge. Can't poll too often.
    if (opts.poll) {
      ee._poll = setInterval(() => {
        getEdgeTasks((err, edgeProcesses) => {
          ee.emit('poll');
          if (err) return ee.emit('error', err);
          if (edgeProcesses.length === 0) {
            clearInterval(ee._poll);
            ee.emit('exit', 0);
          }
        });
      }, opts.pollInterval);
    }

    return cb(null, ee);
  });
}

//Arbitrary Code Execution
function name36(filepath, options) {
  var src = file.read(filepath, options);
  var result;
  grunt.verbose.write('Parsing ' + filepath + '...');
  try {
    result = YAML.load(src);
    grunt.verbose.ok();
    return result;
  } catch (e) {
    grunt.verbose.error();
    throw grunt.util.error('Unable to parse "' + filepath + '" file (' + e.message + ').', e);
  }
}

//Prototype Pollution
function name37(obj, path, value, delimiter) {
  var arr;
  var key;
  if (!obj || typeof obj !== 'object') {
    obj = {};
  }
  if (typeof path === 'string') {
    path = path.split(delimiter || '.');
  }
  if (Array.isArray(path) && path.length > 0) {
    arr = path;
    key = arr[0];
    if (arr.length > 1) {
      arr.shift();
      obj[key] = setPath(obj[key], arr, value, delimiter);
    } else {
      obj[key] = value;
    }
  }
  return obj;
}

//Prototype Pollution
function name38(obj, path, value, delimiter) {
  var arr;
  var key;
  if (!obj || typeof obj !== 'object') {
    obj = {};
  }
  if (typeof path === 'string') {
    path = path.split(delimiter || '.');
  }
  if (Array.isArray(path) && path.length > 0) {
    arr = path;
    key = arr[0];
    if (arr.length > 1) {
      arr.shift();
      obj[key] = setPath(obj[key], arr, value, delimiter);
    } else {
      obj[key] = value;
    }
  }
  return obj;
}

//Command Injection
function sync(os) {
  var stdio = os.stdio===undefined? STDIO:os.stdio;
  return cp.execSync(command(os), {stdio});
}

//Command Injection
function ffmpeg(os) {
  var stdio = os.stdio===undefined? STDIO:os.stdio;
  return new Promise((fres, frej) => cp.exec(command(os), {stdio}, (err, stdout, stderr) => {
    if(err) frej(err);
    else fres({stdout, stderr});
  }));
}

//Prototype Pollution
function reducer(result, arg)
{
  arg = arg.split('=')

  // Get key node
  const keypath = arg.shift().split('.')

  let key = keypath.shift()
  let node = result

  while(keypath.length)
  {
    node[key] = node[key] || {}
    node = node[key]

    key = keypath.shift()
  }

  // Get value
  let val = true
  if(arg.length)
  {
    val = arg.join('=').split(',')
    if(val.length === 1) val = val[0]
  }

  // Store value
  node[key] = val

  return result
}

//Prototype Pollution
function name39(value, prefix) {
      if (!prefix) prefix = [];

      if (Array.isArray(value)) {
        value.forEach(function(arrValue, idx) {
          iter(arrValue, prefix.concat(idx));
        });
      } else if (isPlainObject(value)) {
        Object.keys(value).forEach(function(key) {
          iter(value[key], prefix.concat(key));
        });
      } else {
        entries.push({key: prefix, value: value});
      }
    }

//Prototype Pollution
function name310(config) {
    var entries = [];

    var iter = function(value, prefix) {
      if (!prefix) prefix = [];

      if (Array.isArray(value)) {
        value.forEach(function(arrValue, idx) {
          iter(arrValue, prefix.concat(idx));
        });
      } else if (isPlainObject(value)) {
        Object.keys(value).forEach(function(key) {
          iter(value[key], prefix.concat(key));
        });
      } else {
        entries.push({key: prefix, value: value});
      }
    };

    iter(config);
    return entries;
  }

//Prototype Pollution
function name311(configObj, envObj) {
    var context = {
      config: configObj,
      env: envObj || process.env
    };

    var entries = ConnieLang.getEntries(context.config);

    // iterate until no updates have been made
    var digest = function name312() {
      var updated = false;

      entries.forEach(function(e) {
        var interpreter = ConnieLang.firstInnermostInterpreterFromValue(e.value, context);
        if (!interpreter) return;

        var newValue = interpreter.replaceInValue(e.value, context);
        if (newValue !== e.value) {
          e.value = newValue;
          updated = true;
        }
      });

      return updated;
    };

    while(digest()) ;

    var result = {};
    entries.forEach(function(e) {
      setValue(result, e.key, e.value);
    });

    return result;
  }

//Prototype Pollution
function name313(obj, key, value) {
  var o = obj;
  var keys = Array.isArray(key) ? key : key.split('.');

  for (var x = 1; x < keys.length; ++x) {
    var currentKey = keys[x];
    var lastKey = keys[x - 1];
    if (typeof(currentKey) === 'number') {
      if (!o[lastKey]) { o[lastKey] = []; }
      o = o[lastKey];
    } else if (typeof(currentKey) === 'string') {
      if (!o[lastKey]) { o[lastKey] = {}; }
      o = o[lastKey];
    } else {
      throw new Error('Oopsy, key arrays should only be strings and numbers:', keys);
    }
  }

  o[keys[keys.length - 1]] = value;
  return obj;
}

//Prototype Pollution
function arrowFunc2(obj, path, val, options = {}) {
	if (obj === undefined || obj === null || path === undefined) {
		return obj;
	}
	
	// Clean the path
	path = clean(path);
	
	const pathParts = split(path);
	const part = pathParts.shift();
	
	if (pathParts.length) {
		// Generate the path part in the object if it does not already exist
		obj[part] = decouple(obj[part], options) || {};
		
		// Recurse
		pushVal(obj[part], pathParts.join("."), val, options);
	} else if (part) {
		// We have found the target array, push the value
		obj[part] = decouple(obj[part], options) || [];
		
		if (!(obj[part] instanceof Array)) {
			throw("Cannot push to a path whose leaf node is not an array!");
		}
		
		obj[part].push(val);
	} else {
		// We have found the target array, push the value
		obj = decouple(obj, options) || [];
		
		if (!(obj instanceof Array)) {
			throw("Cannot push to a path whose leaf node is not an array!");
		}
		
		obj.push(val);
	}
	
	return decouple(obj, options);
}

//Prototype Pollution
function arrowFunc3(obj, path, val, options = {}) {
	if (obj === undefined || obj === null || path === undefined) {
		return obj;
	}
	
	// Clean the path
	path = clean(path);
	
	const pathParts = split(path);
	const part = pathParts.shift();
	
	if (pathParts.length) {
		// Generate the path part in the object if it does not already exist
		obj[part] = decouple(obj[part], options) || {};
		
		// Recurse
		pushVal(obj[part], pathParts.join("."), val, options);
	} else if (part) {
		// We have found the target array, push the value
		obj[part] = decouple(obj[part], options) || [];
		
		if (!(obj[part] instanceof Array)) {
			throw("Cannot push to a path whose leaf node is not an array!");
		}
		
		obj[part].push(val);
	} else {
		// We have found the target array, push the value
		obj = decouple(obj, options) || [];
		
		if (!(obj instanceof Array)) {
			throw("Cannot push to a path whose leaf node is not an array!");
		}
		
		obj.push(val);
	}
	
	return decouple(obj, options);
}

//Cross-site Scripting (XSS)
function open(propsData) {
    let slot
    // vnode array
    if (Array.isArray(propsData.message)) {
        slot = propsData.message
        delete propsData.message
    }
    const vm = typeof window !== 'undefined' && window.Vue ? window.Vue : localVueInstance || VueInstance
    const DialogComponent = vm.extend(Dialog)
    const component = new DialogComponent({
        el: document.createElement('div'),
        propsData
    })
    if (slot) {
        component.$slots.default = slot
    }
    if (!config.defaultProgrammaticPromise) {
        return component
    } else {
        return new Promise((resolve) => {
            component.$on('confirm', (event) => resolve({ result: event || true, dialog: component }))
            component.$on('cancel', () => resolve({ result: false, dialog: component }))
        })
    }
}

//Cross-site Scripting (XSS)
function name40 (params) {
        let parent
        if (typeof params === 'string') {
            params = {
                content: params
            }
        }

        const defaultParam = {
            programmatic: true
        }
        if (params.parent) {
            parent = params.parent
            delete params.parent
        }
        let slot
        if (Array.isArray(params.content)) {
            slot = params.content
            delete params.content
        }
        const propsData = merge(defaultParam, params)

        const vm = typeof window !== 'undefined' && window.Vue ? window.Vue : localVueInstance || VueInstance
        const ModalComponent = vm.extend(Modal)
        const instance = new ModalComponent({
            parent,
            el: document.createElement('div'),
            propsData
        })
        if (slot) {
            instance.$slots.default = slot
        }
        return instance
    }

//Cross-site Scripting (XSS)
function name41 (params) {
        let parent
        if (typeof params === 'string') {
            params = {
                message: params
            }
        }

        const defaultParam = {
            position: config.defaultToastPosition || 'is-top'
        }
        if (params.parent) {
            parent = params.parent
            delete params.parent
        }
        let slot
        if (Array.isArray(params.message)) {
            slot = params.message
            delete params.message
        }
        const propsData = merge(defaultParam, params)

        const vm = typeof window !== 'undefined' && window.Vue ? window.Vue : localVueInstance || VueInstance
        const ToastComponent = vm.extend(Toast)
        const instance = new ToastComponent({
            parent,
            el: document.createElement('div'),
            propsData
        })
        if (slot) {
            instance.$slots.default = slot
        }
        return instance
    }

//Cross-site Scripting (XSS)
function name314() {
					this._elt.innerHTML = '<svg viewBox="-20 -20 140 140" width="100" height="100">' +
						'<defs>' +
						'<marker id="prism-previewer-easing-marker" viewBox="0 0 4 4" refX="2" refY="2" markerUnits="strokeWidth">' +
						'<circle cx="2" cy="2" r="1.5" />' +
						'</marker>' +
						'</defs>' +
						'<path d="M0,100 C20,50, 40,30, 100,0" />' +
						'<line x1="0" y1="100" x2="20" y2="50" marker-start="url(' + location.href + '#prism-previewer-easing-marker)" marker-end="url(' + location.href + '#prism-previewer-easing-marker)" />' +
						'<line x1="100" y1="0" x2="40" y2="30" marker-start="url(' + location.href + '#prism-previewer-easing-marker)" marker-end="url(' + location.href + '#prism-previewer-easing-marker)" />' +
						'</svg>';
				}

//Information Exposure
function name315(error) {
  if (!error.response || !error.response.request || !error.response.request._data) {
    return error;
  }

  Object.keys(error.response.request._data).forEach(function(key) {
    if (key.toLowerCase().match('password|secret')) {
      error.response.request._data[key] = '[SANITIZED]';
    }
  });

  return error;
}

//Prototype Pollution
function deepExtend1(target, source, overwrite) {
  /* eslint no-restricted-syntax: 0 */
  for (const prop in source) {
    if (prop !== '__proto__') {
      if (prop in target) {
        // If we reached a leaf string in target or source then replace with source or skip depending on the 'overwrite' switch
        if (
          typeof target[prop] === 'string' ||
          target[prop] instanceof String ||
          typeof source[prop] === 'string' ||
          source[prop] instanceof String
        ) {
          if (overwrite) target[prop] = source[prop];
        } else {
          deepExtend(target[prop], source[prop], overwrite);
        }
      } else {
        target[prop] = source[prop];
      }
    }
  }
  return target;
}

//Regular Expression Denial of Service (ReDoS)
function parse_isodur(s) {
	var sec = 0, mt = 0, time = false;
	var m = s.match(/P([0-9\.]+Y)?([0-9\.]+M)?([0-9\.]+D)?T([0-9\.]+H)?([0-9\.]+M)?([0-9\.]+S)?/);
	if(!m) throw new Error("|" + s + "| is not an ISO8601 Duration");
	for(var i = 1; i != m.length; ++i) {
		if(!m[i]) continue;
		mt = 1;
		if(i > 3) time = true;
		switch(m[i].slice(m[i].length-1)) {
			case 'Y':
				throw new Error("Unsupported ISO Duration Field: " + m[i].slice(m[i].length-1));
			case 'D': mt *= 24;
				/* falls through */
			case 'H': mt *= 60;
				/* falls through */
			case 'M':
				if(!time) throw new Error("Unsupported ISO Duration Field: M");
				else mt *= 60;
				/* falls through */
			case 'S': break;
		}
		sec += mt * parseInt(m[i], 10);
	}
	return sec;
}

//Regular Expression Denial of Service (ReDoS)
function parse_isodur1(s) {
	var sec = 0, mt = 0, time = false;
	var m = s.match(/P([0-9\.]+Y)?([0-9\.]+M)?([0-9\.]+D)?T([0-9\.]+H)?([0-9\.]+M)?([0-9\.]+S)?/);
	if(!m) throw new Error("|" + s + "| is not an ISO8601 Duration");
	for(var i = 1; i != m.length; ++i) {
		if(!m[i]) continue;
		mt = 1;
		if(i > 3) time = true;
		switch(m[i].slice(m[i].length-1)) {
			case 'Y':
				throw new Error("Unsupported ISO Duration Field: " + m[i].slice(m[i].length-1));
			case 'D': mt *= 24;
				/* falls through */
			case 'H': mt *= 60;
				/* falls through */
			case 'M':
				if(!time) throw new Error("Unsupported ISO Duration Field: M");
				else mt *= 60;
				/* falls through */
			case 'S': break;
		}
		sec += mt * parseInt(m[i], 10);
	}
	return sec;
}

//Command Injection
function execTag (newVersion, pkgPrivate, args) {
  let tagOption
  if (args.sign) {
    tagOption = '-s '
  } else {
    tagOption = '-a '
  }
  checkpoint(args, 'tagging release %s%s', [args.tagPrefix, newVersion])
  return runExec(args, 'git tag ' + tagOption + args.tagPrefix + newVersion + ' -m "' + formatCommitMessage(args.releaseCommitMessageFormat, newVersion) + '"')
    .then(() => runExec('', 'git rev-parse --abbrev-ref HEAD'))
    .then((currentBranch) => {
      let message = 'git push --follow-tags origin ' + currentBranch.trim()
      if (pkgPrivate !== true && bump.getUpdatedConfigs()['package.json']) {
        message += ' && npm publish'
        if (args.prerelease !== undefined) {
          if (args.prerelease === '') {
            message += ' --tag prerelease'
          } else {
            message += ' --tag ' + args.prerelease
          }
        }
      }

      checkpoint(args, 'Run `%s` to publish', [message], chalk.blue(figures.info))
    })
}

//Insertion of Sensitive Information into Log File
function logRequest (method, res, startTime, opts) {
  const elapsedTime = Date.now() - startTime
  const attempt = res.headers.get('x-fetch-attempts')
  const attemptStr = attempt && attempt > 1 ? ` attempt #${attempt}` : ''
  const cacheStr = res.headers.get('x-local-cache') ? ' (from cache)' : ''
  opts.log.http(
    'fetch',
    `${method.toUpperCase()} ${res.status} ${res.url} ${elapsedTime}ms${attemptStr}${cacheStr}`
  )
}

//Insertion of Sensitive Information into Log File
function andLogAndFinish (spec, tracker, done) {
  validate('SOF|SZF|OOF|OZF', [spec, tracker, done])
  return (er, pkg) => {
    if (er) {
      log.silly('fetchPackageMetaData', 'error for ' + String(spec), er.message)
      if (tracker) tracker.finish()
    }
    return done(er, pkg)
  }
}

//Command Injection
function getBranches(config, privkey, done) {
  if (config.auth.type === 'ssh') {
    gitane().run({
      cmd: `git ls-remote -h ${gitUrl(config)[0]}`,
      baseDir: '/',
      privKey: config.auth.privkey || privkey,
      detached: true
    }, function (err, stdout, stderr, exitCode) {
      if (err || exitCode !== 0) {
        return done(err || new Error(stderr));
      }

      processBranches(stdout, done);
    });
  } else {
    exec(`git ls-remote -h ${httpUrl(config)[0]}`, function (err, stdout) {
      if (err) return done(err);
      processBranches(stdout, done);
    });
  }
}

//Cross-site Scripting (XSS)
function name316(value, options) {
    if (!value) {
      return '';
    }
    value = this.getWidgetValueAsString(value, options);
    if (Array.isArray(value)) {
      return value.join(', ');
    }
    if (_.isPlainObject(value)) {
      return JSON.stringify(value);
    }
    if (value === null || value === undefined) {
      return '';
    }
    return value.toString();
  }

//Cross-site Scripting (XSS)
function namegetValueAsString(value, options) {
    if (!value) {
      return '';
    }
    value = this.getWidgetValueAsString(value, options);
    if (Array.isArray(value)) {
      return value.join(', ');
    }
    if (_.isPlainObject(value)) {
      return JSON.stringify(value);
    }
    if (value === null || value === undefined) {
      return '';
    }
    return value.toString();
  }

//Remote Code Execution (RCE)
function escapeshellarg (arg) {
  //  discuss at: https://locutus.io/php/escapeshellarg/
  // original by: Felix Geisendoerfer (https://www.debuggable.com/felix)
  // improved by: Brett Zamir (https://brett-zamir.me)
  //   example 1: escapeshellarg("kevin's birthday")
  //   returns 1: "'kevin\\'s birthday'"

  var ret = ''

  ret = arg.replace(/[^\\]'/g, function (m, i, s) {
    return m.slice(0, 1) + '\\\''
  })

  return "'" + ret + "'"
}

//Cross-site Scripting (XSS)
function name42 (req, url, publicUrl, opt_nokey) {
  if (!url || (typeof url !== 'string') || url.indexOf('local://') !== 0) {
    return url;
  }
  const queryParams = [];
  if (!opt_nokey && req.query.key) {
    queryParams.unshift(`key=${req.query.key}`);
  }
  let query = '';
  if (queryParams.length) {
    query = `?${queryParams.join('&')}`;
  }
  return url.replace(
    'local://', utils.getPublicUrl(publicUrl, req)) + query;
}

//Cross-site Scripting (XSS)
function arrowFunc4(child, index) {
          child.index = index
          const childField = child.dom.field
          if (childField) {
            childField.innerHTML = index
          }
        }

//Cross-site Scripting (XSS)
function name43 () {
    const domValue = this.dom.value
    const childs = this.childs
    if (domValue && childs) {
      if (this.type === 'array') {
        childs.forEach((child, index) => {
          child.index = index
          const childField = child.dom.field
          if (childField) {
            childField.innerHTML = index
          }
        })
      } else if (this.type === 'object') {
        childs.forEach(child => {
          if (child.index !== undefined) {
            delete child.index

            if (child.field === undefined) {
              child.field = ''
            }
          }
        })
      }
    }
  }

//Cross-site Scripting (XSS)
function name_updateDomIndexes () {
    const domValue = this.dom.value
    const childs = this.childs
    if (domValue && childs) {
      if (this.type === 'array') {
        childs.forEach((child, index) => {
          child.index = index
          const childField = child.dom.field
          if (childField) {
            childField.innerHTML = index
          }
        })
      } else if (this.type === 'object') {
        childs.forEach(child => {
          if (child.index !== undefined) {
            delete child.index

            if (child.field === undefined) {
              child.field = ''
            }
          }
        })
      }
    }
  }

//Cross-site Scripting (XSS)
function name317(i, option) {
      var item = this.items[option.idx];
      var includes = util.includes(option.textContent.toLowerCase(), string.toLowerCase());

      if (includes && !option.disabled) {

        appendItem(item, f, this.customOption);

        util.removeClass(item, "excluded");

        // Underline the matching results
        if (!this.customOption) {
          item.innerHTML = match(string, option);
        }
      } else {
        util.addClass(item, "excluded");
      }
    }

//Cross-site Scripting (XSS)
function name318(e, a) {
    var d = document,
        el = d.createElement(e);
    if (a && "[object Object]" === Object.prototype.toString.call(a)) {
      var i;
      for (i in a)
        if (i in el) el[i] = a[i];
        else if ("html" === i) el.innerHTML = a[i];
        else if ("text" === i) {
          var t = d.createTextNode(a[i]);
          el.appendChild(t);
        } else el.setAttribute(i, a[i]);
    }
    return el;
  }

//Cross-site Scripting (XSS)
function name319(placeholder) {
  // Set the placeholder
  placeholder = placeholder || this.config.placeholder || this.el.getAttribute("placeholder");

  if (!this.options.length) {
    placeholder = "No options available";
  }

  this.placeEl.innerHTML = placeholder;
}

//Cross-site Scripting (XSS)
row => {
          const divRow = document.createElement('div')
          divRow.className = 'item'
          // divRow.style.color = config.color;
          divRow.onmouseover = onMouseOver
          divRow.onmouseout = onMouseOut
          divRow.onmousedown = onMouseDown
          divRow.__hint = row
          divRow.innerHTML = row.substring(0, token.length) + '<b>' + row.substring(token.length) + '</b>'
          elem.appendChild(divRow)
          return divRow
        }

//Cross-site Scripting (XSS)
function calculateWidthForText (text) {
    if (spacer === undefined) { // on first call only.
      spacer = document.createElement('span')
      spacer.style.visibility = 'hidden'
      spacer.style.position = 'fixed'
      spacer.style.outline = '0'
      spacer.style.margin = '0'
      spacer.style.padding = '0'
      spacer.style.border = '0'
      spacer.style.left = '0'
      spacer.style.whiteSpace = 'pre'
      spacer.style.fontSize = fontSize
      spacer.style.fontFamily = fontFamily
      spacer.style.fontWeight = 'normal'
      document.body.appendChild(spacer)
    }

    // Used to encode an HTML string into a plain text.
    // taken from http://stackoverflow.com/questions/1219860/javascript-jquery-html-encoding
    spacer.innerHTML = String(text).replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
    return spacer.getBoundingClientRect().right
  }

//Insecure Defaults
function Markdown({ source, className = "" }) {
  if (typeof source !== "string") {
    return null
  }

  const md = new Remarkable({
    html: true,
    typographer: true,
    breaks: true,
    linkTarget: "_blank"
  }).use(linkify)

  md.core.ruler.disable(["replacements", "smartquotes"])

  const html = md.render(source)
  const sanitized = sanitizer(html)

  if (!source || !html || !sanitized) {
    return null
  }

  return (
    `<div className={cx(className, "markdown")} dangerouslySetInnerHTML={{ __html: sanitized }}></div>`
  )
}

//Insecure Defaults
function arrowFunc5({ source, className = "" }) {
  if(typeof source !== "string") {
    return null
  }
  
  if ( source ) {
    const html = parser.render(source)
    const sanitized = sanitizer(html)

    let trimmed

    if(typeof sanitized === "string") {
      trimmed = sanitized.trim()
    }

    return (
      `<div
        dangerouslySetInnerHTML={{
          __html: trimmed
        }}
        className={cx(className, "renderedMarkdown")}
      />`
    )
  }
  return null
}

//Command Injection
function name320(files, message, newVer, tagName, callback) {
  message = escapeQuotes(message.replace("%s", newVer));
  files = files.map(escapeQuotes).join(" ");
  var functionSeries = [
    function name321(done) {
      cp.exec(gitApp + " add " + files, gitExtra, done);
    },

    function name322(done) {
      cp.exec([gitApp, "commit", "-m", message].join(" "), gitExtra, done);
    },

    function name323(done) {
      cp.exec(
        [gitApp, "tag", "-a", tagName, "-m", message].join(" "),
        gitExtra,
        done
      );
    },
  ];
  contra.series(functionSeries, callback);
}

//Command Injection
function name324(trainset) {

			// console.log(JSON.stringify(this.modelFileString, null, 4))
			_.each(trainset, function(value, key, list){
				trainset[key].output = 0
			}, this)

			var testFile = svmcommon.writeDatasetToFile(
                                        trainset, this.bias, /*binarize=*/false, "/tmp/test_"+this.timestamp, "SvmLinear", FIRST_FEATURE_NUMBER);

			var command = this.test_command+" "+testFile + " " + this.modelFileString + " /tmp/out_" + this.timestamp;

			var output = child_process.execSync(command)
			console.log(command)

			var result = fs.readFileSync("/tmp/out_" + this.timestamp, "utf-8").split("\n")

			return result
		}

//Remote Code Execution (RCE)
function name325(files, message, newVer, tagName, callback) {
  message = message.replace('%s', newVer).replace('"', '').replace("'", '');
  files = files.map(function (file) {
    return '"' + escapeQuotes(file) + '"';
  }).join(' ');
  var functionSeries = [
    function name326(done) {
      cp.exec(gitApp + ' add ' + files, gitExtra, done);
    },

    function name327(done) {
      cp.exec([gitApp, 'commit', '-m', '"' + message + '"'].join(' '), gitExtra, done);
    },

    function name328(done) {
      cp.exec(
        [
          gitApp, 'tag', '-a', tagName, '-m', '"' + message + '"'
        ].join(' '),
        gitExtra, done
      );
    }
  ];
  contra.series(functionSeries, callback);
}

//Arbitrary Code Execution
function name329($$__fn__$$, options) {
  assert(typeof $$__fn__$$ === 'function')
  options = options || {}
  options.withCallback = true
  if (options.multiArgs === undefined) options.multiArgs = true
  return eval(createWrapper($$__fn__$$.name, options))
}

//Arbitrary Code Execution
function thenify($$__fn__$$, options) {
  assert(typeof $$__fn__$$ === 'function')
  return eval(createWrapper($$__fn__$$.name, options))
}

//Information Exposure
function name330(err, data) {
        if (err) return cb(err)

        if (!isPrivate) {
          if (meta) cb(null, { key, value: data.value, timestamp: data.timestamp })
          else cb(null, data.value)
        }
        else {
          const result = db._unbox(data, unbox)

          if (meta) cb(null, { key, value: result.value, timestamp: result.timestamp })
          else cb(null, result.value)
        }
      }

//Information Exposure
function name331(err, data) {
        if (err) return cb(err)

        if (!isPrivate) {
          if (meta) cb(null, { key, value: data.value, timestamp: data.timestamp })
          else cb(null, data.value)
        }
        else {
          const result = db._unbox(data, unbox)

          if (meta) cb(null, { key, value: result.value, timestamp: result.timestamp })
          else cb(null, result.value)
        }
      }

//Cross-site Scripting (XSS)
function name332(node) {
    fragment.appendChild(node);
  }

//Cross-site Scripting (XSS)
function jqLiteBuildFragment(html, context) {
  var tmp, tag, wrap,
      fragment = context.createDocumentFragment(),
      nodes = [], i;

  if (jqLiteIsTextNode(html)) {
    // Convert non-html into a text node
    nodes.push(context.createTextNode(html));
  } else {
    // Convert html into DOM nodes
    tmp = fragment.appendChild(context.createElement('div'));
    tag = (TAG_NAME_REGEXP.exec(html) || ['', ''])[1].toLowerCase();
    wrap = wrapMap[tag] || wrapMap._default;
    tmp.innerHTML = wrap[1] + html.replace(XHTML_TAG_REGEXP, '<$1></$2>') + wrap[2];

    // Descend through wrappers to the right content
    i = wrap[0];
    while (i--) {
      tmp = tmp.lastChild;
    }

    nodes = concat(nodes, tmp.childNodes);

    tmp = fragment.firstChild;
    tmp.textContent = '';
  }

  // Remove wrapper from fragment
  fragment.textContent = '';
  fragment.innerHTML = ''; // Clear inner HTML
  forEach(nodes, function(node) {
    fragment.appendChild(node);
  });

  return fragment;
}

//Arbitrary File Read
async function requireModule (path) {
  const f = await resolve(path)
  return require(f)
}

//Cross-site Scripting (XSS)
function sanitizeUrl(url) {
  try {
    const decoded = decodeURIComponent(url);

    if (decoded.match(/^\s*javascript:/i)) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn(
          'Anchor URL contains an unsafe JavaScript expression, it will not be rendered.',
          decoded
        );
      }

      return null;
    }
  } catch (e) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn(
        'Anchor URL could not be decoded due to malformed syntax or characters, it will not be rendered.',
        url
      );
    }

    // decodeURIComponent sometimes throws a URIError
    // See `decodeURIComponent('a%AFc');`
    // http://stackoverflow.com/questions/9064536/javascript-decodeuricomponent-malformed-uri-exception
    return null;
  }

  return url;
}

//Arbitrary Code Execution
function parse (string) {
  var match = regex.exec(string)
  if (!match) {
    return {
      attributes: {},
      body: string,
      bodyBegin: 1
    }
  }

  var yaml = match[match.length - 1].replace(/^\s+|\s+$/g, '')
  var attributes = parser.load(yaml) || {}
  var body = string.replace(match[0], '')
  var line = computeLocation(match, string)

  return {
    attributes: attributes,
    body: body,
    bodyBegin: line,
    frontmatter: yaml
  }
}

//Improper Access Control
function name333(message, local, callback, context) {
    var method = Faye.Channel.parse(message.channel)[1],
        response;

    if (Faye.indexOf(this.META_METHODS, method) < 0) {
      response = this._makeResponse(message);
      response.error = Faye.Error.channelForbidden(message.channel);
      response.successful = false;
      return callback.call(context, [response]);
    }

    this[method](message, local, function(responses) {
      responses = [].concat(responses);
      for (var i = 0, n = responses.length; i < n; i++) this._advize(responses[i], message.connectionType);
      callback.call(context, responses);
    }, this);
  }

//Improper Access Control
function name334(response, connectionType) {
    if (Faye.indexOf([Faye.Channel.HANDSHAKE, Faye.Channel.CONNECT], response.channel) < 0)
      return;

    var interval, timeout;
    if (connectionType === 'eventsource') {
      interval = Math.floor(this._engine.timeout * 1000);
      timeout  = 0;
    } else {
      interval = Math.floor(this._engine.interval * 1000);
      timeout  = Math.floor(this._engine.timeout * 1000);
    }

    response.advice = response.advice || {};
    if (response.error) {
      Faye.extend(response.advice, {reconnect:  'handshake'}, false);
    } else {
      Faye.extend(response.advice, {
        reconnect:  'retry',
        interval:   interval,
        timeout:    timeout
      }, false);
    }
  }

//Cross-site Scripting (XSS)
function embedVimeoIframe(e){
		var elem = e.currentTarget;
		var id = elem.getAttribute('data-vimeo');
		var vimeoParams = elem.getAttribute('data-vimeoparams') || '';

		if(vimeoParams && !regAmp.test(vimeoParams)){
			vimeoParams = '&'+ vimeoParams;
		}

		e.preventDefault();

		elem.innerHTML = '<iframe src="' + (vimeoIframe.replace(regId, id)) + vimeoParams +'" ' +
			'frameborder="0" allowfullscreen="" width="640" height="390"></iframe>'
		;

		elem.removeEventListener('click', embedVimeoIframe);
	}

//Cross-site Scripting (XSS)
function embedYoutubeIframe(e){
		var elem = e.currentTarget;
		var id = elem.getAttribute('data-youtube');
		var youtubeParams = elem.getAttribute('data-ytparams') || '';

		if(youtubeParams && !regAmp.test(youtubeParams)){
			youtubeParams = '&'+ youtubeParams;
		}

		e.preventDefault();

		elem.innerHTML = '<iframe src="' + (youtubeIframe.replace(regId, id)) + youtubeParams +'" ' +
			'frameborder="0" allowfullscreen="" width="640" height="390"></iframe>'
		;

		elem.removeEventListener('click', embedYoutubeIframe);
	}

//Cross-site Scripting (XSS)
function f(a){var b=a.currentTarget,c=b.getAttribute("data-vimeo"),d=b.getAttribute("data-vimeoparams")||"";d&&!m.test(d)&&(d="&"+d),a.preventDefault(),b.innerHTML='<iframe src="'+q.replace(k,c)+d+'" frameborder="0" allowfullscreen="" width="640" height="390"></iframe>',b.removeEventListener("click",f)}

//Cross-site Scripting (XSS)
function h(a){var b=a.currentTarget,c=b.getAttribute("data-youtube"),d=b.getAttribute("data-ytparams")||"";d&&!m.test(d)&&(d="&"+d),a.preventDefault(),b.innerHTML='<iframe src="'+o.replace(k,c)+d+'" frameborder="0" allowfullscreen="" width="640" height="390"></iframe>',b.removeEventListener("click",h)}

//Command Injection
function name44 (message, options, callback) {
        message = message.replace(/\"/g, "\\");
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("commit -m \"" + message + "\" " + options, callback)
    }

//Command Injection
function name45 (options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = ".";
        }
        return this.exec("add " + options, callback);
    }

//Command Injection
function name46 (options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("branch " + options, callback);
    }

//Command Injection
function name47 (options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("checkout " + options, callback);
    }

//Command Injection
function name48 (gitUrl, options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("clone " + gitUrl + " " + options, callback);
    }

//Command Injection
function namecommit (message, options, callback) {
        message = message.replace(/\"/g, "\\");
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("commit -m \"" + message + "\" " + options, callback)
    }

//Command Injection
function namepull (options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("pull " + options, callback);
    }

//Command Injection
function nameadd (options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = ".";
        }
        return this.exec("add " + options, callback);
    }

//Command Injection
function namebranch (options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("branch " + options, callback);
    }

//Command Injection
function namecheckout (options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("checkout " + options, callback);
    }

//Command Injection
function nameclone (gitUrl, options, callback) {
        if (typeof options === "function") {
            callback = options;
            options = "";
        }
        return this.exec("clone " + gitUrl + " " + options, callback);
    }

//Cross-site Request Forgery (CSRF)
function name49 (err) {
    // Output full error objects
    err.message = err.stack;
    console.error(err);
    err.expose = true;
    return null;
  }

//Cross-Site Request Forgery (CSRF)
function getOriginOfRequest(req) {
    const origin = req.get('origin');
    const referrer = req.get('referrer');

    if (!origin && !referrer) {
        return null;
    }

    if (origin) {
        return origin;
    }

    const {protocol, host} = url.parse(referrer);
    if (protocol && host) {
        return `${protocol}//${host}`;
    }
    return null;
}

//Prototype Pollution
function name335(obj, path, val) {
  var segs = path.split('.');
  var attr = segs.pop();
  var src = obj;

  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i];
    obj[seg] = obj[seg] || {};
    obj = obj[seg];
  }

  obj[attr] = val;

  return src;
}

//Command Injection
function diskusage(path, cb) {
    if (path.indexOf('"') !== -1) {
        return cb(new Error('Paths with double quotes are not supported yet'));
    }

    exec('df -k "' + path + '"', function(err, stdout) {
        if (err) {
            return cb(err);
        }

        try {
            cb(null, parse(stdout));
        } catch (e) {
            cb(e);
        }
    });
}

//Prototype Pollution
function setDeepProperty(obj, propertyPath, value) {
    const a = splitPath(propertyPath);
    const n = a.length;
    for (let i = 0; i < n - 1; i++) {
        const k = a[i];
        if (!(k in obj)) {
            obj[k] = {};
        }
        obj = obj[k];
    }
    obj[a[n - 1]] = value;
    return;
}

//Prototype Pollution
function name336(obj, path, val) {
  var segs = path.split('.');
  var attr = segs.pop();
  var src = obj;

  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i];
    obj[seg] = obj[seg] || {};
    obj = obj[seg];
  }

  obj[attr] = val;

  return src;
}

//Prototype Pollution
function name337(object, keypath, value) {
    var k, kp, o;
    if (typeof keypath === 'string') {
        keypath = keypath.split('.');
    }
    if (!(keypath instanceof Array)) {
        throw "invalid keypath: " + (JSON.stringify(keypath));
    }
    kp = [].concat(keypath);
    o = object;
    while (kp.length > 1) {
        k = kp.shift();
        if (o[k] == null) {
            if (!Number.isNaN(parseInt(k))) {
                o = o[k] = [];
            } else {
                o = o[k] = {};
            }
        } else {
            o = o[k];
        }
    }
    if (kp.length === 1 && (o != null)) {
        if (value === void 0) {
            delete o[kp[0]];
        } else {
            o[kp[0]] = value;
            if (o[kp[0]] !== value) {
                throw "couldn't set value " + (JSON.stringify(value)) + " for keypath " + (keypath.join('.')) + " in " + (JSON.stringify(object));
            }
        }
    }
    return object;
}

//Command Injection
async function name410 (scanner) {
        const path = this.settings[scanner].path || null;
        if (!path) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not determine path for clamav binary.`);
            return false;
        }

        const version_cmds = {
            clamdscan: `${path} --version`,
            clamscan: `${path} --version`,
        };

        try {
            await fs_access(path, fs.constants.R_OK);

            const {stdout} = await cp_exec(version_cmds[scanner]);
            if (stdout.toString().match(/ClamAV/) === null) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
                return false;
            }
            return true;
        } catch (err) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
            return false;
        }
    }

//Command Injection
async function _is_clamav_binary(scanner) {
        const path = this.settings[scanner].path || null;
        if (!path) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not determine path for clamav binary.`);
            return false;
        }

        const version_cmds = {
            clamdscan: `${path} --version`,
            clamscan: `${path} --version`,
        };

        try {
            await fs_access(path, fs.constants.R_OK);

            const {stdout} = await cp_exec(version_cmds[scanner]);
            if (stdout.toString().match(/ClamAV/) === null) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
                return false;
            }
            return true;
        } catch (err) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
            return false;
        }
    }

//Timing Attack
function pointFpMultiply(b){if(this.isInfinity()){return this}if(b.signum()==0){return this.curve.getInfinity()}var g=b;var f=g.multiply(new BigInteger("3"));var l=this.negate();var d=this;var c;for(c=f.bitLength()-2;c>0;--c){d=d.twice();var a=f.testBit(c);var j=g.testBit(c);if(a!=j){d=d.add(a?this:l)}}return d}

//Timing Attack
function pointFpMultiply1(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();

    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice();

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
	    R = R.add(hBit ? this : neg);
	}
    }

    return R;
}

//Timing Attack
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;

  var R = this.curve.getInfinity();
  var both = this.add(x);
  while(i >= 0) {
    R = R.twice();
    if(j.testBit(i)) {
      if(k.testBit(i)) {
        R = R.add(both);
      }
      else {
        R = R.add(this);
      }
    }
    else {
      if(k.testBit(i)) {
        R = R.add(x);
      }
    }
    --i;
  }

  return R;
}

//Regular Expression Denial of Service (ReDoS)
function name338(list, line) {
      if (isMochaInternal(line)) {
        return list;
      }

      if (is.node && isNodeInternal(line)) {
        return list;
      }

      // Clean up cwd(absolute)
      if (/\(?.+:\d+:\d+\)?$/.test(line)) {
        line = line.replace('(' + cwd, '(');
      }

      list.push(line);
      return list;
    }

//Regular Expression Denial of Service (ReDoS)
function name339(stack) {
    stack = stack.split('\n');

    stack = stack.reduce(function(list, line) {
      if (isMochaInternal(line)) {
        return list;
      }

      if (is.node && isNodeInternal(line)) {
        return list;
      }

      // Clean up cwd(absolute)
      if (/\(?.+:\d+:\d+\)?$/.test(line)) {
        line = line.replace('(' + cwd, '(');
      }

      list.push(line);
      return list;
    }, []);

    return stack.join('\n');
  }

//Improper Authentication
async _ => {
          const from = this.unlockedAccount
          const to = from + n
          this.accounts = []
          for (let i = from; i < to; i++) {
            let address
            if (this._isBIP44()) {
              const path = this._getPathForIndex(i)
              address = await this.unlock(path)
            } else {
              address = this._addressFromIndex(pathBase, i)
            }
            this.accounts.push(address)
            this.page = 0
          }
          resolve(this.accounts)
        }

//Improper Authentication
function arrowFunc6(resolve, reject) {
      this.unlock()
        .then(async _ => {
          const from = this.unlockedAccount
          const to = from + n
          this.accounts = []
          for (let i = from; i < to; i++) {
            let address
            if (this._isBIP44()) {
              const path = this._getPathForIndex(i)
              address = await this.unlock(path)
            } else {
              address = this._addressFromIndex(pathBase, i)
            }
            this.accounts.push(address)
            this.page = 0
          }
          resolve(this.accounts)
        })
        .catch(e => {
          reject(e)
        })
    }

//Improper Authentication
function addAccounts (n = 1) {

    return new Promise((resolve, reject) => {
      this.unlock()
        .then(async _ => {
          const from = this.unlockedAccount
          const to = from + n
          this.accounts = []
          for (let i = from; i < to; i++) {
            let address
            if (this._isBIP44()) {
              const path = this._getPathForIndex(i)
              address = await this.unlock(path)
            } else {
              address = this._addressFromIndex(pathBase, i)
            }
            this.accounts.push(address)
            this.page = 0
          }
          resolve(this.accounts)
        })
        .catch(e => {
          reject(e)
        })
    })
  }

//Improper Authentication
function arrowFunc7(resolve, reject) {
      this.unlock()
        .then(async _ => {
          const from = this.unlockedAccount
          const to = from + n
          this.accounts = []
          for (let i = from; i < to; i++) {
            let address
            if (this._isBIP44()) {
              const path = this._getPathForIndex(i)
              address = await this.unlock(path)
            } else {
              address = this._addressFromIndex(pathBase, i)
            }
            this.accounts.push(address)
            this.page = 0
          }
          resolve(this.accounts)
        })
        .catch(e => {
          reject(e)
        })
    }

//Improper Authentication
function name340(n = 1) {

    return new Promise((resolve, reject) => {
      this.unlock()
        .then(async _ => {
          const from = this.unlockedAccount
          const to = from + n
          this.accounts = []
          for (let i = from; i < to; i++) {
            let address
            if (this._isBIP44()) {
              const path = this._getPathForIndex(i)
              address = await this.unlock(path)
            } else {
              address = this._addressFromIndex(pathBase, i)
            }
            this.accounts.push(address)
            this.page = 0
          }
          resolve(this.accounts)
        })
        .catch(e => {
          reject(e)
        })
    })
  }

//Improper Authentication
function name341(address) {
    if (!this.accounts.map(a => a.toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${address} not found in this keyring`)
    }
    this.accounts = this.accounts.filter(a => a.toLowerCase() !== address.toLowerCase())
  }

//Improper Authentication
function addAccounts1 (n = 1) {

    return new Promise((resolve, reject) => {
      this.unlock()
        .then(async _ => {
          const from = this.unlockedAccount
          const to = from + n
          this.accounts = []
          for (let i = from; i < to; i++) {
            let address
            if (this._isBIP44()) {
              const path = this._getPathForIndex(i)
              address = await this.unlock(path)
            } else {
              address = this._addressFromIndex(pathBase, i)
            }
            this.accounts.push(address)
            this.page = 0
          }
          resolve(this.accounts)
        })
        .catch(e => {
          reject(e)
        })
    })
  }

//Prototype Pollution
function name342(key, index) {
      if (typeof o === 'object' && o[key] === undefined) {
        o[key] = {}
      }

      if (typeof o[key] !== 'object' || Array.isArray(o[key])) {
        // ensure that o[key] is an array, and that the last item is an empty object.
        if (Array.isArray(o[key])) {
          o[key].push({})
        } else {
          o[key] = [o[key], {}]
        }

        // we want to update the empty object at the end of the o[key] array, so set o to that object
        o = o[key][o[key].length - 1]
      } else {
        o = o[key]
      }
    }

//Prototype Pollution
function name343(target, source) {
		for (var name in source) {
			var tval = target[name],
  			    sval = source[name];
			if (tval !== sval) {
				if (shouldDeepCopy(sval)) {
					if (Object.prototype.toString.call(sval) === '[object Date]') { // use this date test to handle crossing frame boundaries
						target[name] = new Date(sval);
					} else if (lang.isArray(sval)) {
 						  target[name] = exports.deepCopyArray(sval);
					} else {
						if (tval && typeof tval === 'object') {
							exports.deepCopy(tval, sval);
						} else {
							target[name] = exports.deepCopy({}, sval);
						}
					}
				} else {
					target[name] = sval;
				}
			}
		}
		return target;
	}

//Regular Expression Denial of Service (ReDoS)
function name344(i) {
    const s = this.source
    const l = s.length
    if (i >= l) {
      return -1
    }
    const c = s.charCodeAt(i)
    if (!this.switchU || c <= 0xD7FF || c >= 0xE000 || i + 1 >= l) {
      return c
    }
    return (c << 10) + s.charCodeAt(i + 1) - 0x35FDC00
  }

//Regular Expression Denial of Service (ReDoS)
function name345(i) {
    const s = this.source
    const l = s.length
    if (i >= l) {
      return l
    }
    const c = s.charCodeAt(i)
    if (!this.switchU || c <= 0xD7FF || c >= 0xE000 || i + 1 >= l) {
      return i + 1
    }
    return i + 2
  }

//Regular Expression Denial of Service (ReDoS)
function nameat(i) {
    const s = this.source
    const l = s.length
    if (i >= l) {
      return -1
    }
    const c = s.charCodeAt(i)
    if (!this.switchU || c <= 0xD7FF || c >= 0xE000 || i + 1 >= l) {
      return c
    }
    return (c << 10) + s.charCodeAt(i + 1) - 0x35FDC00
  }

//Regular Expression Denial of Service (ReDoS)
function namenextIndex(i) {
    const s = this.source
    const l = s.length
    if (i >= l) {
      return l
    }
    const c = s.charCodeAt(i)
    if (!this.switchU || c <= 0xD7FF || c >= 0xE000 || i + 1 >= l) {
      return i + 1
    }
    return i + 2
  }

//Prototype Pollution
function writeConfig(output, key, value, recurse) {
  var k, o;
  if (isObject(value) && !isArray(value)) {
    o = isObject(output[key]) ? output[key] : (output[key] = {});
    for (k in value) {
      if (recurse && (recurse === true || recurse[k])) {
        writeConfig(o, k, value[k]);
      } else {
        o[k] = value[k];
      }
    }
  } else {
    output[key] = value;
  }
}

//Command Injection
function name346(repo, cb) {
	var self = this;
	var dir = this.checkoutDir(repo.organization, repo.name);
	mkdirp(dir, init);

	function init(err) {
		if (err)
			return cb('mkdirp(' + dir + ') failed');
		debug('mkdirp() ' + dir + ' finished');
		child.exec('git init', {
			cwd : dir
		}, function(err, stdo, stde) {
			if (err)
				return cb(err);
			debug('init() ' + dir + ' finished');
			fetch();
		});
	}

	function fetch() {
		var cmd = ['git', 'fetch', 'file://' + path.resolve(self.repoDir, repo.organization, repo.name), repo.branch].join(' ');

		child.exec(cmd, {
			cwd : dir
		}, function(err) {
			if (err)
				return cb(err);
			debug('fetch() ' + dir + ' finished');
			checkout();
		});
	}

	function checkout() {
		var cmd = ['git', 'checkout', '-b', repo.branch, repo.commit].join(' ');

		child.exec(cmd, {
			cwd : dir
		}, function(err, stdo, stde) {
			cb(err, stdo, stde);
		});
	}

}

//Command Injection
function name347(repo, cb) {
	var self = this;
	var dir = this.checkoutDir(repo.organization, repo.name);
	repo.id = repo.commit + '.' + Date.now();
	var cmd = ['git', 'pull', 'file://' + path.resolve(self.repoDir, repo.organization, repo.name), repo.branch].join(' ');
	debug('Git.pull ' + dir + ': ' + cmd);
	child.exec(cmd, {
		cwd : dir
	}, function(err) {
		debug('Git.pull ' + dir + ' done: ' + err);
		if (err)
			return cb(err);
		cb(null);
	});
}

//Remote Code Execution (RCE)
function name411 (commandName, target, message) {
        var that = this;

        // Maximum length of target + message we can send to the IRC server is 500 characters
        // but we need to leave extra room for the sender prefix so the entire message can
        // be sent from the IRCd to the target without being truncated.
        var blocks = [...lineBreak(message, { bytes: this.options.message_max_length, allowBreakingWords: true, allowBreakingGraphemes: true })];

        blocks.forEach(function(block) {
            that.raw(commandName, target, block);
        });

        return blocks;
    }

//Remote Code Execution (RCE)
function namesendMessage(commandName, target, message) {
        var that = this;

        // Maximum length of target + message we can send to the IRC server is 500 characters
        // but we need to leave extra room for the sender prefix so the entire message can
        // be sent from the IRCd to the target without being truncated.
        var blocks = [...lineBreak(message, { bytes: this.options.message_max_length, allowBreakingWords: true, allowBreakingGraphemes: true })];

        blocks.forEach(function(block) {
            that.raw(commandName, target, block);
        });

        return blocks;
    }

//Remote Code Execution (RCE)
function name412 (node, output, state) {
			let code;
			if (node.lang && highlight.getLanguage(node.lang))
				code = highlight.highlight(node.lang, node.content, true); // Discord seems to set ignore ignoreIllegals: true

			if (code && state.cssModuleNames) // Replace classes in hljs output
				code.value = code.value.replace(/<span class="([a-z0-9-_ ]+)">/gi, (str, m) =>
					str.replace(m, m.split(' ').map(cl => state.cssModuleNames[cl] || cl).join(' ')));

			return htmlTag('pre', htmlTag(
				'code', code ? code.value : node.content, { class: `hljs${code ? ' ' + code.language : ''}` }, state
			), null, state);
		}

//Cross-site Scripting (XSS)
function name413 (markup, theme, options) {
		const html = htmlUtils.processImageTags(markup, data => {
			if (!data.src) return null;

			const r = utils.imageReplacement(this.ResourceModel_, data.src, options.resources, this.resourceBaseUrl_);
			if (!r) return null;

			if (typeof r === 'string') {
				return {
					type: 'replaceElement',
					html: r,
				};
			} else {
				return {
					type: 'setAttributes',
					attrs: r,
				};
			}
		});

		const cssStrings = noteStyle(theme, options);
		const styleHtml = `<style>${cssStrings.join('\n')}</style>`;

		return {
			html: styleHtml + html,
			pluginAssets: [],
		};
	}

//Cross-site Scripting (XSS)
function namerender(markup, theme, options) {
		const html = htmlUtils.processImageTags(markup, data => {
			if (!data.src) return null;

			const r = utils.imageReplacement(this.ResourceModel_, data.src, options.resources, this.resourceBaseUrl_);
			if (!r) return null;

			if (typeof r === 'string') {
				return {
					type: 'replaceElement',
					html: r,
				};
			} else {
				return {
					type: 'setAttributes',
					attrs: r,
				};
			}
		});

		const cssStrings = noteStyle(theme, options);
		const styleHtml = `<style>${cssStrings.join('\n')}</style>`;

		return {
			html: styleHtml + html,
			pluginAssets: [],
		};
	}

//Prototype Pollution
function name348(payload, mime, next) {

    // Binary

    if (mime === 'application/octet-stream') {
        return next(null, payload.length ? payload : null);
    }

    // Text

    if (mime.match(/^text\/.+$/)) {
        return next(null, payload.toString('utf8'));
    }

    // JSON

    if (/^application\/(?:.+\+)?json$/.test(mime)) {
        return internals.jsonParse(payload, next);                      // Isolate try...catch for V8 optimization
    }

    // Form-encoded

    if (mime === 'application/x-www-form-urlencoded') {
        const parse = (this.settings.querystring || Querystring.parse);
        return next(null, payload.length ? parse(payload.toString('utf8')) : {});
    }

    return next(Boom.unsupportedMediaType());
}

//Prototype Pollution
function name349(obj, tgt, path) {
  tgt = tgt || {}
  path = path || []
  var isArray = Array.isArray(obj)

  Object.keys(obj).forEach(function (key) {
    var index = isArray && this.useBrackets ? '[' + key + ']' : key
    if (
      (
        isArrayOrObject(obj[key]) &&
        (
          (isObject(obj[key]) && !isEmptyObject(obj[key])) ||
          (Array.isArray(obj[key]) && (!this.keepArray && (obj[key].length !== 0)))
        )
      )
    ) {
      if (isArray && this.useBrackets) {
        var previousKey = path[path.length - 1] || ''
        return this.dot(obj[key], tgt, path.slice(0, -1).concat(previousKey + index))
      } else {
        return this.dot(obj[key], tgt, path.concat(index))
      }
    } else {
      if (isArray && this.useBrackets) {
        tgt[path.join(this.separator).concat('[' + key + ']')] = obj[key]
      } else {
        tgt[path.concat(index).join(this.separator)] = obj[key]
      }
    }
  }.bind(this))
  return tgt
}

//Prototype Pollution
function name350(obj, tgt, path) {
  tgt = tgt || {}
  path = path || []
  var isArray = Array.isArray(obj)

  Object.keys(obj).forEach(function (key) {
    var index = isArray && this.useBrackets ? '[' + key + ']' : key
    if (
      (
        isArrayOrObject(obj[key]) &&
        (
          (isObject(obj[key]) && !isEmptyObject(obj[key])) ||
          (Array.isArray(obj[key]) && (!this.keepArray && (obj[key].length !== 0)))
        )
      )
    ) {
      if (isArray && this.useBrackets) {
        var previousKey = path[path.length - 1] || ''
        return this.dot(obj[key], tgt, path.slice(0, -1).concat(previousKey + index))
      } else {
        return this.dot(obj[key], tgt, path.concat(index))
      }
    } else {
      if (isArray && this.useBrackets) {
        tgt[path.join(this.separator).concat('[' + key + ']')] = obj[key]
      } else {
        tgt[path.concat(index).join(this.separator)] = obj[key]
      }
    }
  }.bind(this))
  return tgt
}

//Command Injection
function createMuteOgg(outputFile, options) {
    return new Promise((resolve, reject) => {
        const ch = options.numOfChannels === 1 ? 'mono' : 'stereo';
        child_process_1.exec('ffmpeg -f lavfi -i anullsrc=r=' +
            options.sampleRate +
            ':cl=' +
            ch +
            ' -t ' +
            options.seconds +
            ' -c:a libvorbis ' +
            outputFile, (error, stdout, stderr) => {
            if (error)
                return reject(error);
            resolve(true);
        });
    });
}

//Command Injection
function name351(path, opts, cb) {
  if (!cb) {
    cb = opts;
    opts = {};
  }

  var cmd = module.exports.cmd(path, opts);
  opts.timeout = opts.timeout || 5000;

  exec(cmd, opts, function(e, stdout, stderr) {
    if (e) { return cb(e); }
    if (stderr) { return cb(new Error(stderr)); }

    return cb(null, module.exports.parse(path, stdout, opts));
  });
}

//Cross-site Scripting (XSS)
function name352( event ) {
				var data = event.data;

				// Make sure we're dealing with JSON
				if( typeof data === 'string' && data.charAt( 0 ) === '{' && data.charAt( data.length - 1 ) === '}' ) {
					data = JSON.parse( data );

					// Check if the requested method can be found
					if( data.method && typeof Reveal[data.method] === 'function' ) {
						var result = Reveal[data.method].apply( Reveal, data.args );

						// Dispatch a postMessage event with the returned value from
						// our method invocation for getter functions
						dispatchPostMessage( 'callback', { method: data.method, result: result } );
					}
				}
			}

//Cross-site Scripting (XSS)
function setupPostMessage() {

		if( config.postMessage ) {
			window.addEventListener( 'message', function ( event ) {
				var data = event.data;

				// Make sure we're dealing with JSON
				if( typeof data === 'string' && data.charAt( 0 ) === '{' && data.charAt( data.length - 1 ) === '}' ) {
					data = JSON.parse( data );

					// Check if the requested method can be found
					if( data.method && typeof Reveal[data.method] === 'function' ) {
						var result = Reveal[data.method].apply( Reveal, data.args );

						// Dispatch a postMessage event with the returned value from
						// our method invocation for getter functions
						dispatchPostMessage( 'callback', { method: data.method, result: result } );
					}
				}
			}, false );
		}

	}

//Internal Property Tampering
function name353(schema, candidate, callback) {
			if (typeof callback === 'function') {
				return this.asyncItems(schema, candidate, callback);
			}
			if (!(schema.items instanceof Object) || !(candidate instanceof Object)) {
				return;
			}
			var items = schema.items;
			var i, l;
			// If provided schema is an array
			// then call validate for each case
			// else it is an Object
			// then call validate for each key
			if (_typeIs.array(items) && _typeIs.array(candidate)) {
				for (i = 0, l = items.length; i < l; i++) {
					this._deeperArray(i);
					this._validate(items[i], candidate[i]);
					this._back();
				}
			}
			else {
				for (var key in candidate) {
					if (candidate.hasOwnProperty(key)){
						this._deeperArray(key);
						this._validate(items, candidate[key]);
						this._back();
					}

				}
			}
		}

//Internal Property Tampering
function name354(schema, post, callback) {
			if (typeof callback === 'function') {
				return this.asyncItems(schema, post, callback);
			}
			if (!(schema.items instanceof Object) || !(post instanceof Object)) {
				return post;
			}
			var i;
			if (_typeIs.array(schema.items) && _typeIs.array(post)) {
				var minLength = schema.items.length < post.length ? schema.items.length : post.length;
				for (i = 0; i < minLength; i++) {
					this._deeperArray(i);
					post[i] = this._sanitize(schema.items[i], post[i]);
					this._back();
				}
			}
			else {
				for (i in post) {
					if(post.hasOwnProperty(i)){
						this._deeperArray(i);
						post[i] = this._sanitize(schema.items, post[i]);
						this._back();
					}
				}
			}
			return post;
		}

//Internal Property Tampering
function name355(schema) {
			var o = {};
			var prop = schema.properties || {};

			for (var key in prop) {
				if (prop.hasOwnProperty(key)){
					if (prop[key].optional === true && _rand.bool() === true) {
						continue;
					}
					if (key !== '*') {
						o[key] = this.generate(prop[key]);
					}
					else {
						var rk = '__random_key_';
						var randomKey = rk + 0;
						var n = _rand.int(1, 9);
						for (var i = 1; i <= n; i++) {
							if (!(randomKey in prop)) {
								o[randomKey] = this.generate(prop[key]);
							}
							randomKey = rk + i;
						}
					}
				}
			}
			return o;
		}

//Internal Property Tampering
function Inspection(schema, custom) {
		var _stack = ['@'];

		this._schema = schema;
		this._custom = {};
		if (custom != null) {
			for (var key in custom) {
				if (custom.hasOwnProperty(key)){
					this._custom['$' + key] = custom[key];
				}
			}
		}

		this._getDepth = function name356() {
			return _stack.length;
		};

		this._dumpStack = function name357() {
			return _stack.map(function (i) {return i.replace(/^\[/g, '\u001b\u001c\u001d\u001e');})
			.join('.').replace(/\.\u001b\u001c\u001d\u001e/g, '[');
		};

		this._deeperObject = function name358(name) {
			_stack.push((/^[a-z$_][a-z0-9$_]*$/i).test(name) ? name : '["' + name + '"]');
			return this;
		};

		this._deeperArray = function name359(i) {
			_stack.push('[' + i + ']');
			return this;
		};

		this._back = function name360() {
			_stack.pop();
			return this;
		};
	}

//Cross-site Scripting (XSS)
function name361() {

    this.response.payload.code = this.response.code;
    this.response.payload.error = Http.STATUS_CODES[this.response.code] || 'Unknown';
    if (this.message) {
        this.response.payload.message = this.message;
    }
}

//Cross-site Scripting (XSS)
function name362(url, width, height) {
					var attrs  = '';

					if (width) {
						attrs += ' width="' + width + '"';
					}

					if (height) {
						attrs += ' height="' + height + '"';
					}

					editor.wysiwygEditorInsertHtml(
						'<img' + attrs + ' src="' + url + '" />'
					);
				}

//Cross-site Scripting (XSS)
function name363(email, text) {
					// needed for IE to reset the last range
					editor.focus();

					if (!editor.getRangeHelper().selectedHtml() || text) {
						editor.wysiwygEditorInsertHtml(
							'<a href="' + 'mailto:' + email + '">' +
								(text || email) +
							'</a>'
						);
					} else {
						editor.execCommand('createlink', 'mailto:' + email);
					}
				}

//Cross-site Scripting (XSS)
function name364(url, text) {
				// needed for IE to restore the last range
				editor.focus();

				// If there is no selected text then must set the URL as
				// the text. Most browsers do this automatically, sadly
				// IE doesn't.
				if (text || !editor.getRangeHelper().selectedHtml()) {
					text = text || url;

					editor.wysiwygEditorInsertHtml(
						'<a href="' + url + '">' + text + '</a>'
					);
				} else {
					editor.execCommand('createlink', url);
				}
			}

//Cross-site Scripting (XSS)
function name365(caller) {
			var	editor  = this;

			defaultCmds.image._dropDown(
				editor,
				caller,
				'',
				function name366(url, width, height) {
					var attrs  = '';

					if (width) {
						attrs += ' width="' + width + '"';
					}

					if (height) {
						attrs += ' height="' + height + '"';
					}

					editor.wysiwygEditorInsertHtml(
						'<img' + attrs + ' src="' + url + '" />'
					);
				}
			);
		}

//Cross-site Scripting (XSS)
function name367(caller) {
			var	editor  = this;

			defaultCmds.email._dropDown(
				editor,
				caller,
				function name368(email, text) {
					// needed for IE to reset the last range
					editor.focus();

					if (!editor.getRangeHelper().selectedHtml() || text) {
						editor.wysiwygEditorInsertHtml(
							'<a href="' + 'mailto:' + email + '">' +
								(text || email) +
							'</a>'
						);
					} else {
						editor.execCommand('createlink', 'mailto:' + email);
					}
				}
			);
		}

//Cross-site Scripting (XSS)
function name369(caller) {
			var editor = this;

			defaultCmds.link._dropDown(editor, caller, function (url, text) {
				// needed for IE to restore the last range
				editor.focus();

				// If there is no selected text then must set the URL as
				// the text. Most browsers do this automatically, sadly
				// IE doesn't.
				if (text || !editor.getRangeHelper().selectedHtml()) {
					text = text || url;

					editor.wysiwygEditorInsertHtml(
						'<a href="' + url + '">' + text + '</a>'
					);
				} else {
					editor.execCommand('createlink', url);
				}
			});
		}

//Cross-site Scripting (XSS)
function name370(caller, html, author) {
			var	before = '<blockquote>',
				end    = '</blockquote>';

			// if there is HTML passed set end to null so any selected
			// text is replaced
			if (html) {
				author = (author ? '<cite>' + author + '</cite>' : '');
				before = before + author + html + end;
				end    = null;
			// if not add a newline to the end of the inserted quote
			} else if (this.getRangeHelper().selectedHtml() === '') {
				end = (IE_BR_FIX ? '' : '<br />') + end;
			}

			this.wysiwygEditorInsertHtml(before, end);
		}

//Cross-site Scripting (XSS)
function arrowFunc8(item, i) {
      const img = item.querySelector('img');
      const image = document.createElement('img');

      image.src = getData(img, 'originalUrl');
      image.alt = img.getAttribute('alt');
      total += 1;
      addClass(image, CLASS_FADE);
      toggleClass(image, CLASS_TRANSITION, options.transition);

      if (hasClass(item, CLASS_ACTIVE)) {
        addClass(image, CLASS_IN);
        index = i;
      }

      list.push(image);
      addListener(image, EVENT_LOAD, onLoad, {
        once: true,
      });
      player.appendChild(image);
    }

//Cross-site Scripting (XSS)
function arrowFunc9(image, i) {
      const { src } = image;
      const alt = image.alt || getImageNameFromURL(src);
      let { url } = options;

      if (isString(url)) {
        url = image.getAttribute(url);
      } else if (isFunction(url)) {
        url = url.call(this, image);
      }

      if (src || url) {
        items.push('<li>'
          + '<img'
            + ` src="${src || url}"`
            + ' role="button"'
            + ' data-viewer-action="view"'
            + ` data-index="${i}"`
            + ` data-original-url="${url || src}"`
            + ` alt="${alt}"`
          + '>'
        + '</li>');
      }
    }

//Cross-site Scripting (XSS)
function sanitizeURL(url) {
    if (url.trim().toLowerCase().indexOf('javascript:') === 0) {
        return 'about:blank';
    }
    return url;
}

//Directory Traversal
function sanitizePath(id, name, callback) {
    if (name[0] === '/') name = name.substring(1);

    if (!id) {
        if (typeof callback === 'function') {
            callback('Empty ID');
        }
        return;
    }

    if (id) {
        id = id.replace(/\.\./g, ''); // do not allow to write in parent directories
    }

    if (name.indexOf('..') !== -1) {
        name = path.normalize(name);
        name = name.replace(/\\/g, '/');
    }
    if (name[0] === '/') name = name.substring(1); // do not allow absolute paths

    return {id: id, name: name};
}

//Prototype Pollution
function name371(obj, field) {
    if (!obj) {
      return obj;
    }
    if (String(field) === 'constructor' && !obj.propertyIsEnumerable(field)) {
      return undefined;
    }
    return obj[field];
  }

//Prototype Pollution
function name372(instance) {
  instance.registerHelper('lookup', function(obj, field) {
    if (!obj) {
      return obj;
    }
    if (String(field) === 'constructor' && !obj.propertyIsEnumerable(field)) {
      return undefined;
    }
    return obj[field];
  });
}

//Prototype Pollution
function baseExtend1(dst, objs, deep) {
  var h = dst.$$hashKey;

  for (var i = 0, ii = objs.length; i < ii; ++i) {
    var obj = objs[i];
    if (!isObject(obj) && !isFunction(obj)) continue;
    var keys = Object.keys(obj);
    for (var j = 0, jj = keys.length; j < jj; j++) {
      var key = keys[j];
      var src = obj[key];

      if (deep && isObject(src)) {
        if (isDate(src)) {
          dst[key] = new Date(src.valueOf());
        } else if (isRegExp(src)) {
          dst[key] = new RegExp(src);
        } else if (src.nodeName) {
          dst[key] = src.cloneNode(true);
        } else if (isElement(src)) {
          dst[key] = src.clone();
        } else {
          if (!isObject(dst[key])) dst[key] = isArray(src) ? [] : {};
          baseExtend(dst[key], [src], true);
        }
      } else {
        dst[key] = src;
      }
    }
  }

  setHashKey(dst, h);
  return dst;
}

//Timing Attack
function getNAF(num, w) {
  var naf = [];
  var ws = 1 << (w + 1);
  var k = num.clone();
  while (k.cmpn(1) >= 0) {
    var z;
    if (k.isOdd()) {
      var mod = k.andln(ws - 1);
      if (mod > (ws >> 1) - 1)
        z = (ws >> 1) - mod;
      else
        z = mod;
      k.isubn(z);
    } else {
      z = 0;
    }
    naf.push(z);

    // Optimization, shift by word if possible
    var shift = (k.cmpn(0) !== 0 && k.andln(ws - 1) === 0) ? (w + 1) : 1;
    for (var i = 1; i < shift; i++)
      naf.push(0);
    k.iushrn(shift);
  }

  return naf;
}

//Prototype Pollution
function extend1(target, source) {
  let key;
  for (key in source) {
    if (isPlainObject(source[key]) || isArray(source[key])) {
      if (isPlainObject(source[key]) && !isPlainObject(target[key])) {
        target[key] = {};
      }
      if (isArray(source[key]) && !isArray(target[key])) {
        target[key] = [];
      }
      extend(target[key], source[key]);
    } else if (source[key] !== undefined) {
      target[key] = source[key];
    }
  }
}

//Unauthorized File Access
function name414 (dir)  {
            return (path.normalize(dir ? path.resolve(repoDir, dir) : repoDir));
        }

//Unauthorized File Access
function name415 (repoDir, options={}) {
    // super();

    if(typeof repoDir === 'function') {
        this.dirMap = repoDir;
    } else {
        this.dirMap = (dir) => {
            return (path.normalize(dir ? path.resolve(repoDir, dir) : repoDir));
        };
    }

    this.authenticate = options.authenticate;
    this.autoCreate = options.autoCreate === false ? false : true;
    this.checkout = options.checkout;
  }

//Unauthorized File Access
function nameconstructor1(repoDir, options={}) {
    // super();

    if(typeof repoDir === 'function') {
        this.dirMap = repoDir;
    } else {
        this.dirMap = (dir) => {
            return (path.normalize(dir ? path.resolve(repoDir, dir) : repoDir));
        };
    }

    this.authenticate = options.authenticate;
    this.autoCreate = options.autoCreate === false ? false : true;
    this.checkout = options.checkout;
  }

//Denial of Service (DoS)
function installMixin (Vue, vueVersion) {
  Vue.mixin({
    ...vueVersion === '1' ? {
      init: initProvider,
    } : {},

    ...vueVersion === '2' ? {
      data () {
        return {
          '$apolloData': {
            queries: {},
            loading: 0,
            data: this.$_apolloInitData,
          },
        }
      },

      beforeCreate () {
        initProvider.call(this)
        proxyData.call(this)
      },

      serverPrefetch () {
        if (this.$_apolloPromises) {
          return Promise.all(this.$_apolloPromises)
        }
      },
    } : {},

    created: launch,

    destroyed: destroy,
  })
}

//SQL Injection
function name416 (value) {
    return value !== '*' ? `[${value.replace(/\[/g, '[')}]` : '*';
  }

//Denial of Service (DoS)
function stripCustomNsAttrs(node) {
    while (node) {
      if (node.nodeType === window.Node.ELEMENT_NODE) {
        var attrs = node.attributes;
        for (var i = 0, l = attrs.length; i < l; i++) {
          var attrNode = attrs[i];
          var attrName = attrNode.name.toLowerCase();
          if (attrName === 'xmlns:ns1' || attrName.lastIndexOf('ns1:', 0) === 0) {
            node.removeAttributeNode(attrNode);
            i--;
            l--;
          }
        }
      }

      var nextNode = node.firstChild;
      if (nextNode) {
        stripCustomNsAttrs(nextNode);
      }

      node = node.nextSibling;
    }
  }

//Man-in-the-Middle (MitM)
function onsocket(socket) {
    // replay the "buffers" Buffer onto the `socket`, since at this point
    // the HTTP module machinery has been hooked up for the user
    if (socket.listenerCount('data') > 0) {
      socket.emit('data', buffers);
    } else {
      // never?
      throw new Error('should not happen...');
    }

    socket.resume();
    // nullify the cached Buffer instance
    buffers = null;
  }

//Cross-site Scripting (XSS)
function name373(event) {
        try {
            var msg = "";

            msg += "<div>";
            msg += event.message;
            msg += "</div>";

            msg += " <div class=\"noVNC_location\">";
            msg += event.filename;
            msg += ":" + event.lineno + ":" + event.colno;
            msg += "</div>";

            if ((event.error !== undefined) &&
                (event.error.stack !== undefined)) {
                msg += "<div class=\"noVNC_stack\">";
                msg += event.error.stack;
                msg += "</div>";
            }

            document.getElementById('noVNC_fallback_error')
                .classList.add("noVNC_open");
            document.getElementById('noVNC_fallback_errormsg').innerHTML = msg;
        } catch (exc) {
            document.write("noVNC encountered an error.");
        }
        // Don't return true since this would prevent the error
        // from being printed to the browser console.
        return false;
    }

//Regular Expression Denial of Service (ReDoS)
function __isInt(value) {
      return /^(\-|\+)?([1-9]+[0-9]*)$/.test(value);
    }

//Regular Expression Denial of Service (ReDoS)
function name417 (value){
    return /^(\-|\+)?([1-9]+[0-9]*)$/.test(value)
  }

//Regular Expression Denial of Service (ReDoS)
function __isInt1(value){
    return /^(\-|\+)?([1-9]+[0-9]*)$/.test(value)
  }

//Cross-site Scripting (XSS)
function name418 (file, i) { return `<li><a download="${file.name}" href="/${i}/${file.name}">${file.path}</a> (${file.length} bytes)</li>`}

//Cross-site Scripting (XSS)
function serveIndexPage () {
      res.statusCode = 200
      res.setHeader('Content-Type', 'text/html')

      const listHtml = torrent.files.map((file, i) => `<li><a download="${file.name}" href="/${i}/${file.name}">${file.path}</a> (${file.length} bytes)</li>`).join('<br>')

      const html = getPageHTML(
        `${torrent.name} - WebTorrent`,
        `<h1>${torrent.name}</h1><ol>${listHtml}</ol>`
      )
      res.end(html)
    }

//Cross-site Scripting (XSS)
function name419 () {
		const button = new ButtonView( this.locale );
		const bind = this.bindTemplate;
		const t = this.t;

		button.set( {
			withText: true,
			tooltip: t( 'Open link in new tab' )
		} );

		button.extendTemplate( {
			attributes: {
				class: [
					'ck',
					'ck-link-actions__preview'
				],
				href: bind.to( 'href' ),
				target: '_blank'
			}
		} );

		button.bind( 'label' ).to( this, 'href', href => {
			return href || t( 'This link has no URL' );
		} );

		button.bind( 'isEnabled' ).to( this, 'href', href => !!href );

		button.template.tag = 'a';
		button.template.eventListeners = {};

		return button;
	}

//Cross-site Scripting (XSS)
function name_createPreviewButton() {
		const button = new ButtonView( this.locale );
		const bind = this.bindTemplate;
		const t = this.t;

		button.set( {
			withText: true,
			tooltip: t( 'Open link in new tab' )
		} );

		button.extendTemplate( {
			attributes: {
				class: [
					'ck',
					'ck-link-actions__preview'
				],
				href: bind.to( 'href' ),
				target: '_blank'
			}
		} );

		button.bind( 'label' ).to( this, 'href', href => {
			return href || t( 'This link has no URL' );
		} );

		button.bind( 'isEnabled' ).to( this, 'href', href => !!href );

		button.template.tag = 'a';
		button.template.eventListeners = {};

		return button;
	}

//Cross-site Scripting (XSS)
function name420 (encodings) {
        let table = "<table class='table table-hover table-sm table-bordered table-nonfluid'><tr><th>Encoding</th><th>Value</th></tr>";

        for (const enc in encodings) {
            const value = Utils.printable(encodings[enc], true);
            table += `<tr><td>${enc}</td><td>${value}</td></tr>`;
        }

        table += "<table>";
        return table;
    }

//Cross-site Scripting (XSS)
function namepresent(encodings) {
        let table = "<table class='table table-hover table-sm table-bordered table-nonfluid'><tr><th>Encoding</th><th>Value</th></tr>";

        for (const enc in encodings) {
            const value = Utils.printable(encodings[enc], true);
            table += `<tr><td>${enc}</td><td>${value}</td></tr>`;
        }

        table += "<table>";
        return table;
    }

//Cross-site Scripting (XSS)
function name374(msg) {
      var $msg = $("<div>" + msg + "</div>");
      this.$region.html($msg);
    }

//Arbitrary Code Execution
function name421 (node, initialScope) {
        const object = getStaticValueR(node.object, initialScope)
        const property = node.computed
            ? getStaticValueR(node.property, initialScope)
            : { value: node.property.name }

        if (object != null && property != null) {
            return { value: object.value[property.value] }
        }
        return null
    }

//Arbitrary Code Execution
function name422 (node, initialScope) {
        const callee = getStaticValueR(node.callee, initialScope)
        const args = getElementValues(node.arguments, initialScope)

        if (callee != null && args != null) {
            const Func = callee.value
            return { value: new Func(...args) }
        }

        return null
    }

//Arbitrary Code Execution
function name423 (node, initialScope) {
        const tag = getStaticValueR(node.tag, initialScope)
        const expressions = getElementValues(
            node.quasi.expressions,
            initialScope
        )

        if (tag != null && expressions != null) {
            const func = tag.value
            const strings = node.quasi.quasis.map(q => q.value.cooked)
            strings.raw = node.quasi.quasis.map(q => q.value.raw)

            return { value: func(strings, ...expressions) }
        }

        return null
    }

//Arbitrary Code Execution
function getElementValues(nodeList, initialScope) {
    const valueList = []

    for (let i = 0; i < nodeList.length; ++i) {
        const elementNode = nodeList[i]

        if (elementNode == null) {
            valueList.length = i + 1
        } else if (elementNode.type === "SpreadElement") {
            const argument = getStaticValueR(elementNode.argument, initialScope)
            if (argument == null) {
                return null
            }
            valueList.push(...argument.value)
        } else {
            const element = getStaticValueR(elementNode, initialScope)
            if (element == null) {
                return null
            }
            valueList.push(element.value)
        }
    }

    return valueList
}

//Message Signature Bypass
async function createVerificationObjects(signatureList, literalDataList, keys, date=new Date()) {
  return Promise.all(signatureList.map(async function(signature) {
    return createVerificationObject(signature, literalDataList, keys, date);
  }));
}

//Cross-site Scripting (XSS)
function name375(req, res, next) {
	var url = req.query.url,
		data = {
			url: url,
			title: meta.config.title,
			breadcrumbs: helpers.buildBreadcrumbs([{text: '[[notifications:outgoing_link]]'}])
		};

	if (url) {
		res.render('outgoing', data);
	} else {
		res.status(404).redirect(nconf.get('relative_path') + '/404');
	}
}

//Arbitrary Command Injection
function connectToWifi(config, ap, callback) {
  var commandStr =
    "nmcli -w 10 device wifi connect '" +
    ap.ssid +
    "'" +
    ' password ' +
    "'" +
    ap.password +
    "'";

  if (config.iface) {
    commandStr = commandStr + ' ifname ' + config.iface;
  }

  exec(commandStr, { env: env }, function(err, resp) {
    // Errors from nmcli came from stdout, we test presence of 'Error: ' string
    if (resp.includes('Error: ')) {
      err = new Error(resp.replace('Error: ', ''));
    }
    callback && callback(err);
  });
}

//Arbitrary Command Injection
function deleteConnection1(config, ap, callback) {
  var commandStr = 'nmcli connection delete id ';

  commandStr += ' ' + "'" + ap.ssid + "'";

  exec(commandStr, env, function(err) {
    callback && callback(err);
  });
}

//Arbitrary Command Injection
function disconnect(config, callback) {
  var commandStr = 'nmcli device disconnect';

  if (config.iface) {
    commandStr += ' ' + config.iface;
  }

  exec(commandStr, { env }, function(err) {
    callback && callback(err);
  });
}

//Arbitrary Command Injection
function connectToWifi1(config, ap, callback) {
  var iface = 'en0';
  var commandStr = 'networksetup -setairportnetwork ';

  if (config.iface) {
    iface = config.iface.toString();
  }

  commandStr =
    commandStr +
    "'" +
    iface +
    "'" +
    ' ' +
    "'" +
    ap.ssid +
    "'" +
    ' ' +
    "'" +
    ap.password +
    "'";
  //console.log(commandStr);

  exec(commandStr, { env }, function(err, resp) {
    //console.log(stderr, resp);
    if (resp && resp.indexOf('Failed to join network') >= 0) {
      callback && callback(resp);
    } else if (resp && resp.indexOf('Could not find network') >= 0) {
      callback && callback(resp);
    } else {
      callback && callback(err);
    }
  });
}

//Arbitrary Command Injection
function getCurrentConnections(config, callback) {
  var commandStr = macProvider + ' --getinfo';

  exec(commandStr, env, function(err, stdout) {
    if (err) {
      callback && callback(err);
    } else {
      callback && callback(null, parseAirport(stdout));
    }
  });
}

//Arbitrary Command Injection
function deleteConnection(config, ap, callback) {
  var iface = 'en0';
  var commandStr = 'networksetup -removepreferredwirelessnetwork ';

  if (config.iface) {
    iface = config.iface.toString();
  }

  commandStr = commandStr + "'" + iface + "'" + ' ' + "'" + ap.ssid + "'";

  exec(commandStr, env, function(err, resp) {
    if (
      resp &&
      resp.indexOf('was not found in the preferred networks list') >= 0
    ) {
      callback && callback(resp);
    } else {
      callback && callback(err);
    }
  });
}

//Arbitrary Command Injection
function name376() {
      var cmd =
        'netsh wlan connect ssid="' + ap.ssid + '" name="' + ap.ssid + '"';
      if (config.iface) {
        cmd += ' interface="' + config.iface + '"';
      }
      return execCommand(cmd);
    }

//Arbitrary Command Injection
function name377(err) {
      exec('netsh wlan delete profile "' + ap.ssid + '"', { env }, function() {
        callback && callback(err);
      });
    }

//Directory Traversal
function name378(src,dest,callback)
	{
		switch(_os.type())
		{
			case 'Windows_NT' :
				_cp.exec('robocopy "'+src+'" "'+dest+'" /e',
					function(err,stdout,stderr)
					{
						if( err && err.code == 1 )
							callback(undefined,stdout,stderr);
						else
							callback(err,stdout,stderr);
					});
				break;
				
			case 'Linux'  :
			case 'Darwin' :
				_cp.exec('cp -R "'+src+'" "'+dest+'"',callback);
				break;

			default:
				throw 'unsupported OS :: '+_os.type();
		}
	}

//Directory Traversal
function name379(dir,callback)
	{
        var split_dir = dir.split('/'),
            curr_dir = '';
        for (var i in split_dir) {
            curr_dir += split_dir[i] + '/';
            if (!_fs.existsSync(curr_dir)) {
                _fs.mkdir(curr_dir, 484, function(err) {if (err) {if (err.code != 'EEXIST') callback(err);}});
            }
        }
        callback();
	}

//Directory Traversal
function name380(dir,callback)
	{
		switch(_os.type())
		{
			case 'Windows_NT' :
				_cp.exec('rmdir /s "'+dir+'"',callback);
				break;
				
			case 'Linux'  :
			case 'Darwin' :
				_cp.exec('rm -rf "'+dir+'"',callback);
				break;

			default:
				throw 'unsupported OS :: '+_os.type();
		}
	}

//Directory Traversal
function name381(path) {
   if( _fs.existsSync(path) ) {
       _fs.readdirSync(path).forEach(function(file,index){
           var curPath = path + "/" + file;
           if(_fs.lstatSync(curPath).isDirectory()) { // recurse
               exports.deleteFolderRecursive(curPath);
           } else { // delete file
               _fs.unlinkSync(curPath);
           }
       });
       _fs.rmdirSync(path);
   }
}

//Cross-site Scripting (XSS)
function name382(entry) {

        if (!entry.id) {
          throw new Error('entry must have an id');
        }

        var html = entry.html;

        if (typeof html === 'string') {
          html = domify(html);
        }

        // unwrap jquery
        if (html.get && html.constructor.prototype.jquery) {
          html = html.get(0);
        }

        var entryNode = domify('<div class="bpp-properties-entry" data-entry="' + entry.id + '"></div>');

        forEach(entry.cssClasses || [], function(cssClass) {
          domClasses(entryNode).add(cssClass);
        });

        entryNode.appendChild(html);

        groupNode.appendChild(entryNode);

        // update conditionally visible elements
        self.updateState(entry, entryNode);
      }

//Cross-site Scripting (XSS)
function name383(option) {
    var optionEntry = domify('<option value="' + option.value + '">' + option.label + '</option>');
    selectBox.appendChild(optionEntry);
  }

//Cross-site Scripting (XSS)
function updateOptionsDropDown(domSelector, businessObject, referencedType, entryNode) {
  var options = refreshOptionsModel(businessObject, referencedType);
  addEmptyParameter(options);
  var selectBox = domQuery(domSelector, entryNode);
  domClear(selectBox);

  forEach(options, function(option) {
    var optionEntry = domify('<option value="' + option.value + '">' + option.label + '</option>');
    selectBox.appendChild(optionEntry);
  });
  return options;
}

//Cross-site Scripting (XSS)
function name384(element, inputNode) {
      // note: this generated id will be used as name
      // of the element and not as id
      var id = utils.nextId(newElementIdPrefix);

      var optionTemplate = domify('<option value="' + id + '"> (id='+id+')' + '</option>');

      // add new option
      var selectBox = getSelectBox(inputNode);
      selectBox.insertBefore(optionTemplate, selectBox.firstChild);

      // select new element in the select box
      forEach(selectBox, function(option) {
        if (option.value === id) {
          domAttr(option, 'selected', 'selected');
        } else {
          domAttr(option, 'selected', null);
        }
      });

      return true;
    }

//Cross-site Scripting (XSS)
function name385(value) {
    return '<option value="' + value + '" data-value data-name="extensionElementValue">' + value + '</option>';
  }

//Cross-site Scripting (XSS)
function name386(entry) {

        if (!entry.id) {
          throw new Error('entry must have an id');
        }

        var html = entry.html;

        if (typeof html === 'string') {
          html = domify(html);
        }

        // unwrap jquery
        if (html.get && html.constructor.prototype.jquery) {
          html = html.get(0);
        }

        var entryNode = domify('<div class="bpp-properties-entry" data-entry="' + entry.id + '"></div>');

        forEach(entry.cssClasses || [], function name387(cssClass) {
          domClasses(entryNode).add(cssClass);
        });

        entryNode.appendChild(html);

        groupNode.appendChild(entryNode);

        // update conditionally visible elements
        self.updateState(entry, entryNode);
      }

//Cross-site Scripting (XSS)
function name388(option) {
    var optionEntry = domify('<option value="' + option.value + '">' + option.label + '</option>');
    selectBox.appendChild(optionEntry);
  }

//Cross-site Scripting (XSS)
function updateOptionsDropDown1(domSelector, businessObject, referencedType, entryNode) {
  var options = refreshOptionsModel(businessObject, referencedType);
  addEmptyParameter(options);
  var selectBox = domQuery(domSelector, entryNode);
  domClear(selectBox);

  forEach(options, function(option) {
    var optionEntry = domify('<option value="' + option.value + '">' + option.label + '</option>');
    selectBox.appendChild(optionEntry);
  });
  return options;
}

//Cross-site Scripting (XSS)
function name389(element, inputNode) {
      // note: this generated id will be used as name
      // of the element and not as id
      var id = utils.nextId(newElementIdPrefix);

      var optionTemplate = domify('<option value="' + id + '"> (id='+id+')' + '</option>');

      // add new option
      var selectBox = getSelectBox(inputNode);
      selectBox.insertBefore(optionTemplate, selectBox.firstChild);

      // select new element in the select box
      forEach(selectBox, function(option) {
        if (option.value === id) {
          domAttr(option, 'selected', 'selected');
        } else {
          domAttr(option, 'selected', null);
        }
      });

      return true;
    }

//Cross-site Scripting (XSS)
function name390(value) {
    return '<option value="' + value + '" data-value data-name="extensionElementValue">' + value + '</option>';
  }

//Cross-site Scripting (XSS)
function name391(entry) {

        if (!entry.id) {
          throw new Error('entry must have an id');
        }

        var html = entry.html;

        if (typeof html === 'string') {
          html = domify(html);
        }

        // unwrap jquery
        if (html.get && html.constructor.prototype.jquery) {
          html = html.get(0);
        }

        var entryNode = domify('<div class="bpp-properties-entry" data-entry="' + entry.id + '"></div>');

        forEach(entry.cssClasses || [], function(cssClass) {
          domClasses(entryNode).add(cssClass);
        });

        entryNode.appendChild(html);

        groupNode.appendChild(entryNode);

        // update conditionally visible elements
        self.updateState(entry, entryNode);
      }

//Cross-site Scripting (XSS)
function name392(option) {
    var optionEntry = domify('<option value="' + option.value + '">' + option.label + '</option>');
    selectBox.appendChild(optionEntry);
  }

//Cross-site Scripting (XSS)
function updateOptionsDropDown2(domSelector, businessObject, referencedType, entryNode) {
  var options = refreshOptionsModel(businessObject, referencedType);
  addEmptyParameter(options);
  var selectBox = domQuery(domSelector, entryNode);
  domClear(selectBox);

  forEach(options, function(option) {
    var optionEntry = domify('<option value="' + option.value + '">' + option.label + '</option>');
    selectBox.appendChild(optionEntry);
  });
  return options;
}

//Cross-site Scripting (XSS)
function name393(element, inputNode) {
      // note: this generated id will be used as name
      // of the element and not as id
      var id = utils.nextId(newElementIdPrefix);

      var optionTemplate = domify('<option value="' + id + '"> (id='+id+')' + '</option>');

      // add new option
      var selectBox = getSelectBox(inputNode);
      selectBox.insertBefore(optionTemplate, selectBox.firstChild);

      // select new element in the select box
      forEach(selectBox, function(option) {
        if (option.value === id) {
          domAttr(option, 'selected', 'selected');
        } else {
          domAttr(option, 'selected', null);
        }
      });

      return true;
    }

//Cross-site Scripting (XSS)
function name394(value) {
    return '<option value="' + value + '" data-value data-name="extensionElementValue">' + value + '</option>';
  }

//Cross-site Scripting (XSS)
function isUrl(string) {
    var regexp = /^(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-/]))?/;
    return regexp.test(string);
  }

//Cross-site Scripting (XSS)
function converted1([key, value]) {
  return `<pre><strong>${key}</strong>: ${value}</pre>`;
}

//Cross-site Scripting (XSS)
function name395()
	{
		var color = input.value;
		ColorDialog.addRecentColor(color, 12);
		
		if (color != 'none' && color.charAt(0) != '#')
		{
			color = '#' + color;
		}

		applyFunction(color);
		editorUi.hideDialog();
	}

//Cross-site Scripting (XSS)
function arrowFunc10(value) {
            if (props.suggestionText) {
              return `<div><strong>${props.suggestionText}</strong> ${value[props.displayKey]}</div>`;
            }
            return `<div>${value.value}</div>`;
          }

//Directory Traversal
function arrowFunc11(Options, FilePath) {

	const Slash = FilePath.split ("")[FilePath.split ("").length - 1] === "/";

	switch (FilePath) {

		case "/": return `${Options.RootFolder}/${Options.IndexFile}`;
		default: return (Slash ? `${Options.RootFolder}${FilePath.slice (0, -1)}` : `${Options.RootFolder}${FilePath}`);
	}
}

//Cross-site Scripting (XSS)
function converted2(elem, property, value) {
  return elem.innerHTML = value || state[property].value;
}

//Prototype Pollution
function set2(target, path, value, options) {
  if (!isObject(target)) {
    return target;
  }

  let opts = options || {};
  const isArray = Array.isArray(path);
  if (!isArray && typeof path !== 'string') {
    return target;
  }

  let merge = opts.merge;
  if (merge && typeof merge !== 'function') {
    merge = Object.assign;
  }

  const keys = isArray ? path : split(path, opts);
  const len = keys.length;
  const orig = target;

  if (!options && keys.length === 1) {
    result(target, keys[0], value, merge);
    return target;
  }

  for (let i = 0; i < len; i++) {
    let prop = keys[i];

    if (!isObject(target[prop])) {
      target[prop] = {};
    }

    if (i === len - 1) {
      result(target, prop, value, merge);
      break;
    }

    target = target[prop];
  }

  return orig;
}

//Prototype Pollution
function mixinDeep(target, ...rest) {
  for (let obj of rest) {
    if (isObject(obj)) {
      for (let key in obj) {
        if (key !== '__proto__') {
          mixin(target, obj[key], key);
        }
      }
    }
  }
  return target;
}

//Prototype Pollution
function arrowFunc12(target, ...args) {
  let i = 0;
  if (isPrimitive(target)) target = args[i++];
  if (!target) target = {};
  for (; i < args.length; i++) {
    if (isObject(args[i])) {
      for (const key of Object.keys(args[i])) {
        if (isObject(target[key]) && isObject(args[i][key])) {
          assign(target[key], args[i][key]);
        } else {
          target[key] = args[i][key];
        }
      }
      assignSymbols(target, args[i]);
    }
  }
  return target;
}

//Cross-site Scripting (XSS)
function name396(t) {
    if (t.matched) {
      htmlText += '<strong class="' + SearchPad.RESULT_HIGHLIGHT_CLASS + '">' + t.matched + '</strong>';
    } else {
      htmlText += t.normal;
    }
  }

//Cross-site Scripting (XSS)
function createHtmlText(tokens) {
  var htmlText = '';

  tokens.forEach(function(t) {
    if (t.matched) {
      htmlText += '<strong class="' + SearchPad.RESULT_HIGHLIGHT_CLASS + '">' + t.matched + '</strong>';
    } else {
      htmlText += t.normal;
    }
  });

  return htmlText !== '' ? htmlText : null;
}

//Cross-site Scripting (XSS)
function name397(t) {
    if (t.matched) {
      htmlText += '<strong class="' + SearchPad.RESULT_HIGHLIGHT_CLASS + '">' + t.matched + '</strong>';
    } else {
      htmlText += t.normal;
    }
  }

//Cross-site Scripting (XSS)
function createHtmlText1(tokens) {
  var htmlText = '';

  tokens.forEach(function(t) {
    if (t.matched) {
      htmlText += '<strong class="' + SearchPad.RESULT_HIGHLIGHT_CLASS + '">' + t.matched + '</strong>';
    } else {
      htmlText += t.normal;
    }
  });

  return htmlText !== '' ? htmlText : null;
}

//Denial of Service (DoS)
function name398() {
    let parts = data.split('.');
    let payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    if (payload.action === 'LOGOUT') {
      let sessionIDs = payload.adapterSessionIds;
      if (!sessionIDs) {
        keycloak.grantManager.notBefore = payload.notBefore;
        response.send('ok');
        return;
      }
      if (sessionIDs && sessionIDs.length > 0) {
        let seen = 0;
        sessionIDs.forEach(id => {
          keycloak.unstoreGrant(id);
          ++seen;
          if (seen === sessionIDs.length) {
            response.send('ok');
          }
        });
      } else {
        response.send('ok');
      }
    }
  }

//Denial of Service (DoS)
function adminLogout (request, response, keycloak) {
  let data = '';

  request.on('data', d => {
    data += d.toString();
  });

  request.on('end', function () {
    let parts = data.split('.');
    let payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    if (payload.action === 'LOGOUT') {
      let sessionIDs = payload.adapterSessionIds;
      if (!sessionIDs) {
        keycloak.grantManager.notBefore = payload.notBefore;
        response.send('ok');
        return;
      }
      if (sessionIDs && sessionIDs.length > 0) {
        let seen = 0;
        sessionIDs.forEach(id => {
          keycloak.unstoreGrant(id);
          ++seen;
          if (seen === sessionIDs.length) {
            response.send('ok');
          }
        });
      } else {
        response.send('ok');
      }
    }
  });
}

//Cross-site Request Forgery (CSRF)
function name399(req) {
	if (req.body && req.body[exports.TOKEN_KEY]) {
		return req.body[exports.TOKEN_KEY];
	} else if (req.query && req.query[exports.TOKEN_KEY]) {
		return req.query[exports.TOKEN_KEY];
	} else if (req.headers && req.headers[exports.XSRF_HEADER_KEY]) {
		return req.headers[exports.XSRF_HEADER_KEY];
	} else if (req.headers && req.headers[exports.CSRF_HEADER_KEY]) {
		return req.headers[exports.CSRF_HEADER_KEY];
	} else if (req.cookies && req.cookies[exports.XSRF_COOKIE_KEY]) {
		return req.cookies[exports.XSRF_COOKIE_KEY];
	}
	return '';
}

//Cross-site Scripting (XSS)
function name424 () {
    const opts = this.element.find('option:selected');
    let text = this.getOptionText(opts);

    if (opts.hasClass('clear')) {
      text = '';
    }

    if (this.settings.empty && opts.length === 0) {
      this.pseudoElem.find('span').html(`<span class="audible">${this.label.text()} </span>`);
      return;
    }

    // Displays the text on the pseudo-element
    const maxlength = this.element.attr('maxlength');
    if (maxlength) {
      text = text.substr(0, maxlength);
    }
    text = text.trim();
    this.pseudoElem.find('span').html(`<span class="audible">${this.label.text()} </span>${text}`);

    // If there is a placeholder  the selected text
    if (this.element.attr('placeholder')) {
      this.pseudoElem.find('span').not('.audible').attr('data-selected-text', text);
    }

    // Set the "previousActiveDescendant" to the first of the items
    this.previousActiveDescendant = opts.first().val();

    this.updateItemIcon(opts);
    this.setBadge(opts);
  }

//Arbitrary Code Injection
function name3100(req, res)  {
      console.log(req.query)
      let curl = `curl -m 3 -s '${req.query.url}'`
      let t0 = Date.now()
      exec(curl, (err, stdout, stderr) => {
        let sample = {
          exit: err ? err.code : 0,
          time: Date.now() - t0,
          stdout: stdout.length,
          stderr: stderr.length
        }
        res.send(JSON.stringify(sample))
      })
    }

//Cross-site Scripting (XSS)
function name3101() {
    const opts = this.element.find('option:selected');
    let text = this.getOptionText(opts);

    if (opts.hasClass('clear')) {
      text = '';
    }

    if (this.settings.empty && opts.length === 0) {
      this.pseudoElem.find('span').html(`<span class="audible">${this.label.text()} </span>`);
      return;
    }

    // Displays the text on the pseudo-element
    const maxlength = this.element.attr('maxlength');
    if (maxlength) {
      text = text.substr(0, maxlength);
    }
    text = text.trim();
    this.pseudoElem.find('span').html(`<span class="audible">${this.label.text()} </span>${text}`);

    // If there is a placeholder  the selected text
    if (this.element.attr('placeholder')) {
      this.pseudoElem.find('span').not('.audible').attr('data-selected-text', text);
    }

    // Set the "previousActiveDescendant" to the first of the items
    this.previousActiveDescendant = opts.first().val();

    this.updateItemIcon(opts);
    this.setBadge(opts);
  }

//Regular Expression Denial of Service (ReDoS)
function isSafe(userAgent) {
  var consecutive = 0
    , code = 0;

  for (var i = 0; i < userAgent.length; i++) {
    code = userAgent.charCodeAt(i);
    // numbers between 0 and 9, letters between a and z
    if ((code >= 48 && code <= 57) || (code >= 97 && code <= 122)) {
      consecutive++;
    } else {
      consecutive = 0;
    }

    if (consecutive >= 100) {
      return false;
    }
  }

  return true
}

//Arbitrary File Overwrite
function statCb (er, current) {
    if (self.filter && !self.filter.call(who, who, current)) {
      self._aborted = true
      self.emit('end')
      self.emit('close')
      return
    }

    // if it's not there, great.  We'll just create it.
    // if it is there, then we'll need to change whatever differs
    if (er || !current) {
      return create(self)
    }

    self._old = current
    var currentType = getType(current)

    // if it's a type change, then we need to clobber or error.
    // if it's not a type change, then let the impl take care of it.
    if (currentType !== self.type) {
      return rimraf(self._path, function (er) {
        if (er) return self.error(er)
        self._old = null
        create(self)
      })
    }

    // otherwise, just handle in the app-specific way
    // this creates a fs.WriteStream, or mkdir's, or whatever
    create(self)
  }

//Cross-site Scripting (XSS)
function name3102(id) {
    if (typeof vertices[id] !== 'undefined') {
      vertices[id].link = linkStr
    }
  }

//Cross-site Scripting (XSS)
function name3103(ids, linkStr, tooltip) {
  ids.split(',').forEach(function (id) {
    if (typeof vertices[id] !== 'undefined') {
      vertices[id].link = linkStr
    }
  })
  setTooltip(ids, tooltip)
  setClass(ids, 'clickable')
}

//Cross-site Scripting (XSS)
function name3104(ids, linkStr) {
  ids.split(',').forEach(function (id) {
    let rawTask = findTaskById(id)
    if (typeof rawTask !== 'undefined') {
      pushFun(id, () => { window.open(linkStr, '_self') })
    }
  })
  setClass(ids, 'clickable')
}

//Cross-site Scripting (XSS)
function name3105(val) {
    this.hidePopover();
    this.textarea.val(val);
    this.body.get(0).innerHTML = val;
    this.formatter.format();
    this.formatter.decorate();
    this.util.reflow(this.body);
    this.inputManager.lastCaretPosition = null;
    return this.trigger('valuechanged');
  }

//Cross-site Scripting (XSS)
function name3106(val) {
    this.hidePopover();
    this.textarea.val(val);
    this.body.get(0).innerHTML = val;
    this.formatter.format();
    this.formatter.decorate();
    this.util.reflow(this.body);
    this.inputManager.lastCaretPosition = null;
    return this.trigger('valuechanged');
  }

//Cross-site Scripting (XSS)
function name425 (capture, parse, state) {
        const [, whitespace] = capture[3].match(HTML_LEFT_TRIM_AMOUNT_R);
        const trimmer = new RegExp(`^${whitespace}`, 'gm');
        const trimmed = capture[3].replace(trimmer, '');

        const parseFunc = containsBlockSyntax(trimmed)
          ? parseBlock
          : parseInline;

        const noInnerParse =
          DO_NOT_PROCESS_HTML_ELEMENTS.indexOf(capture[1]) !== -1;

        return {
          attrs: attrStringToMap(capture[2]),
          /**
           * if another html block is detected within, parse as block,
           * otherwise parse as inline to pick up any further markdown
           */
          content: noInnerParse ? capture[3] : parseFunc(parse, trimmed, state),

          noInnerParse,

          tag: capture[1],
        };
      }

//Arbitrary File Overwrite
function name3107() {
        var srcpath = path.resolve(cwd, header.linkname)

        xfs.link(srcpath, name, function (err) {
          if (err && err.code === 'EPERM' && opts.hardlinkAsFilesFallback) {
            stream = xfs.createReadStream(srcpath)
            return onfile()
          }

          stat(err)
        })
      }

//Arbitrary File Overwrite
function name3108() {
      if (win32) return next() // skip links on win for now before it can be tested
      xfs.unlink(name, function () {
        var srcpath = path.resolve(cwd, header.linkname)

        xfs.link(srcpath, name, function (err) {
          if (err && err.code === 'EPERM' && opts.hardlinkAsFilesFallback) {
            stream = xfs.createReadStream(srcpath)
            return onfile()
          }

          stat(err)
        })
      })
    }

//Cross-site Scripting (XSS)
function name3109(html) {
  if (!SAFE_PARSING_SUPPORTED) {
    return '';
  }

  var newTree = this.processToTree(html);
  if (noclobber.getElementAttributes(newTree).length > 0) {
    // We want to preserve the outer SPAN tag, because the processor has
    // attached attributes to it. To do so, we make a new SPAN tag the parent of
    // the existing root span tag, so that the rest of the function will remove
    // that one instead.
    var newRoot = googDom.createElement(TagName.SPAN);
    newRoot.appendChild(newTree);
    newTree = newRoot;
  }
  // The XMLSerializer will add a spurious xmlns attribute to the root node.
  var serializedNewTree = new XMLSerializer().serializeToString(newTree);
  // Remove the outer span before returning the string representation of the
  // processed copy.
  return serializedNewTree.slice(
      serializedNewTree.indexOf('>') + 1, serializedNewTree.lastIndexOf('</'));
}

//Timing Attack
function staticUsersAuthorizer(username, password) {
        for(var i in users)
            if(username == i && password == users[i])
                return true

        return false
    }

//Sensitive Data Exposure
function name426 (uri, config) {
    const regExp = new RegExp(':?' + (config.password || '') + '@');
    return uri.replace(regExp, ':*****@');
  }

//Prototype Pollution
function name3110(obj, field) {
    return obj && obj[field];
  }

//Prototype Pollution
function name3111(instance) {
  instance.registerHelper('lookup', function(obj, field) {
    return obj && obj[field];
  });
}

//Arbitrary File Overwrite
function arrowFunc13(er, st) {
        if (st && (this.keep || this.newer && st.mtime > entry.mtime))
          this[SKIP](entry)
        else if (er || (entry.type === 'File' && !this.unlink && st.isFile()))
          this[MAKEFS](null, entry)
        else if (st.isDirectory()) {
          if (entry.type === 'Directory') {
            if (!entry.mode || (st.mode & 0o7777) === entry.mode)
              this[MAKEFS](null, entry)
            else
              fs.chmod(entry.absolute, entry.mode, er => this[MAKEFS](er, entry))
          } else
            fs.rmdir(entry.absolute, er => this[MAKEFS](er, entry))
        } else
          fs.unlink(entry.absolute, er => this[MAKEFS](er, entry))
      }

//Arbitrary File Overwrite
er => {
      if (er)
        return this[ONERROR](er, entry)
      fs.lstat(entry.absolute, (er, st) => {
        if (st && (this.keep || this.newer && st.mtime > entry.mtime))
          this[SKIP](entry)
        else if (er || (entry.type === 'File' && !this.unlink && st.isFile()))
          this[MAKEFS](null, entry)
        else if (st.isDirectory()) {
          if (entry.type === 'Directory') {
            if (!entry.mode || (st.mode & 0o7777) === entry.mode)
              this[MAKEFS](null, entry)
            else
              fs.chmod(entry.absolute, entry.mode, er => this[MAKEFS](er, entry))
          } else
            fs.rmdir(entry.absolute, er => this[MAKEFS](er, entry))
        } else
          fs.unlink(entry.absolute, er => this[MAKEFS](er, entry))
      })
    }

//Arbitrary File Overwrite
function name427 (entry) {
    this[PEND]()
    this[MKDIR](path.dirname(entry.absolute), this.dmode, er => {
      if (er)
        return this[ONERROR](er, entry)
      fs.lstat(entry.absolute, (er, st) => {
        if (st && (this.keep || this.newer && st.mtime > entry.mtime))
          this[SKIP](entry)
        else if (er || (entry.type === 'File' && !this.unlink && st.isFile()))
          this[MAKEFS](null, entry)
        else if (st.isDirectory()) {
          if (entry.type === 'Directory') {
            if (!entry.mode || (st.mode & 0o7777) === entry.mode)
              this[MAKEFS](null, entry)
            else
              fs.chmod(entry.absolute, entry.mode, er => this[MAKEFS](er, entry))
          } else
            fs.rmdir(entry.absolute, er => this[MAKEFS](er, entry))
        } else
          fs.unlink(entry.absolute, er => this[MAKEFS](er, entry))
      })
    })
  }

//Arbitrary File Overwrite
function name428 (entry) {
    const er = this[MKDIR](path.dirname(entry.absolute), this.dmode)
    if (er)
      return this[ONERROR](er, entry)
    try {
      const st = fs.lstatSync(entry.absolute)
      if (this.keep || this.newer && st.mtime > entry.mtime)
        return this[SKIP](entry)
      else if (entry.type === 'File' && !this.unlink && st.isFile())
        return this[MAKEFS](null, entry)
      else {
        try {
          if (st.isDirectory()) {
            if (entry.type === 'Directory') {
              if (entry.mode && (st.mode & 0o7777) !== entry.mode)
                fs.chmodSync(entry.absolute, entry.mode)
            } else
              fs.rmdirSync(entry.absolute)
          } else
            fs.unlinkSync(entry.absolute)
          return this[MAKEFS](null, entry)
        } catch (er) {
          return this[ONERROR](er, entry)
        }
      }
    } catch (er) {
      return this[MAKEFS](null, entry)
    }
  }

//Arbitrary File Overwrite
function name3112(entry) {
    this[PEND]()
    this[MKDIR](path.dirname(entry.absolute), this.dmode, er => {
      if (er)
        return this[ONERROR](er, entry)
      fs.lstat(entry.absolute, (er, st) => {
        if (st && (this.keep || this.newer && st.mtime > entry.mtime))
          this[SKIP](entry)
        else if (er || (entry.type === 'File' && !this.unlink && st.isFile()))
          this[MAKEFS](null, entry)
        else if (st.isDirectory()) {
          if (entry.type === 'Directory') {
            if (!entry.mode || (st.mode & 0o7777) === entry.mode)
              this[MAKEFS](null, entry)
            else
              fs.chmod(entry.absolute, entry.mode, er => this[MAKEFS](er, entry))
          } else
            fs.rmdir(entry.absolute, er => this[MAKEFS](er, entry))
        } else
          fs.unlink(entry.absolute, er => this[MAKEFS](er, entry))
      })
    })
  }

//Arbitrary File Overwrite
function name3113(entry) {
    const er = this[MKDIR](path.dirname(entry.absolute), this.dmode)
    if (er)
      return this[ONERROR](er, entry)
    try {
      const st = fs.lstatSync(entry.absolute)
      if (this.keep || this.newer && st.mtime > entry.mtime)
        return this[SKIP](entry)
      else if (entry.type === 'File' && !this.unlink && st.isFile())
        return this[MAKEFS](null, entry)
      else {
        try {
          if (st.isDirectory()) {
            if (entry.type === 'Directory') {
              if (entry.mode && (st.mode & 0o7777) !== entry.mode)
                fs.chmodSync(entry.absolute, entry.mode)
            } else
              fs.rmdirSync(entry.absolute)
          } else
            fs.unlinkSync(entry.absolute)
          return this[MAKEFS](null, entry)
        } catch (er) {
          return this[ONERROR](er, entry)
        }
      }
    } catch (er) {
      return this[MAKEFS](null, entry)
    }
  }

//Prototype Pollution
function InstallDots(o) {
	this.__path 		= o.path || "./";
	if (this.__path[this.__path.length-1] !== '/') this.__path += '/';
	this.__destination	= o.destination || this.__path;
	if (this.__destination[this.__destination.length-1] !== '/') this.__destination += '/';
	this.__global		= o.global || "window.render";
	this.__rendermodule	= o.rendermodule || {};
	this.__settings 	= o.templateSettings ? copy(o.templateSettings, copy(doT.templateSettings)) : undefined;
	this.__includes		= {};
}

//Cross-site Scripting (XSS)
function name3114(url /* : ?string */) {
    if (url == null) {
        return null;
    }
    try {
        var prot = decodeURIComponent(url)
            .replace(/[^A-Za-z0-9/:]/g, '')
            .toLowerCase();
        if (prot.indexOf('javascript:') === 0) {
            return null;
        }
    } catch (e) {
        // decodeURIComponent sometimes throws a URIError
        // See `decodeURIComponent('a%AFc');`
        // http://stackoverflow.com/questions/9064536/javascript-decodeuricomponent-malformed-uri-exception
        return null;
    }
    return url;
}

//Arbitrary Code Execution
function name429 (code) {
    if (typeof code !== 'string') {
      throw new TypeError('not a string')
    }
    return vm.runInContext(
      '(function () {"use strict"; return ' + code + '})()',
      this._context,
      this._options
    )
  }

//Arbitrary Code Execution
function namerunInContext (code) {
    if (typeof code !== 'string') {
      throw new TypeError('not a string')
    }
    return vm.runInContext(
      '(function () {"use strict"; return ' + code + '})()',
      this._context,
      this._options
    )
  }

//Timing Attack
function nativeTimingSafeEqual(a, b) {
    var strA = String(a);
    var strB = String(b);
    
    var len = Math.max(Buffer.byteLength(strA), Buffer.byteLength(strB));
    
    var bufA = bufferAlloc(len, 0, 'utf8');
    bufA.write(strA);
    var bufB = bufferAlloc(len, 0, 'utf8');
    bufB.write(strB);
    
    return crypto.timingSafeEqual(bufA, bufB);
}

//Content Injection
function name430 (req, res) {
        let limit = parseInt(req.query.limit, 10);
        if (!Number.isInteger(limit)) limit = 0;
        const result = this.logHandler.logs.slice(limit * -1);
        res.send(JSON.stringify(result));
      }

//Content Injection
function name431 () {
    const apiRoute = '/embark-api/process-logs/' + this.processName;
    this.embark.registerAPICall(
      'ws',
      apiRoute,
      (ws, _req) => {
        this.events.on('process-log-' + this.processName, function (log) {
          ws.send(JSON.stringify(log), () => {});
        });
      }
    );
    this.embark.registerAPICall(
      'get',
      '/embark-api/process-logs/' + this.processName,
      (req, res) => {
        let limit = parseInt(req.query.limit, 10);
        if (!Number.isInteger(limit)) limit = 0;
        const result = this.logHandler.logs.slice(limit * -1);
        res.send(JSON.stringify(result));
      }
    );
  }

//Content Injection
function nameregisterAPICalls() {
    const apiRoute = '/embark-api/process-logs/' + this.processName;
    this.embark.registerAPICall(
      'ws',
      apiRoute,
      (ws, _req) => {
        this.events.on('process-log-' + this.processName, function (log) {
          ws.send(JSON.stringify(log), () => {});
        });
      }
    );
    this.embark.registerAPICall(
      'get',
      '/embark-api/process-logs/' + this.processName,
      (req, res) => {
        let limit = parseInt(req.query.limit, 10);
        if (!Number.isInteger(limit)) limit = 0;
        const result = this.logHandler.logs.slice(limit * -1);
        res.send(JSON.stringify(result));
      }
    );
  }

//Insufficient Entropy
function encrypt(value) {
        if (value == null) {
            throw new Error('value must not be null or undefined');
        }

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        const encrypted = cipher.update(String(value), 'utf8', 'hex') + cipher.final('hex');

        return iv.toString('hex') + encrypted;
    }

//Insufficient Entropy
function decrypt(value) {
        if (value == null) {
            throw new Error('value must not be null or undefined');
        }

        const stringValue = String(value);
        const iv = Buffer.from(stringValue.slice(0, 32), 'hex');
        const encrypted = stringValue.slice(32);

        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
    }

//Cross-site Scripting (XSS)
function name432 ($element, content) {
    const html = this.config.html
    if (typeof content === 'object' && (content.nodeType || content.jquery)) {
      // Content is a DOM node or a jQuery
      if (html) {
        if (!$(content).parent().is($element)) {
          $element.empty().append(content)
        }
      } else {
        $element.text($(content).text())
      }
    } else {
      $element[html ? 'html' : 'text'](content)
    }
  }

//Cross-site Scripting (XSS)
function namesetElementContent($element, content) {
    const html = this.config.html
    if (typeof content === 'object' && (content.nodeType || content.jquery)) {
      // Content is a DOM node or a jQuery
      if (html) {
        if (!$(content).parent().is($element)) {
          $element.empty().append(content)
        }
      } else {
        $element.text($(content).text())
      }
    } else {
      $element[html ? 'html' : 'text'](content)
    }
  }

//Information Exposure
function name3115(pathIN, pathOUT, password, callback) {
  var params = [
    'pkcs12',
    '-in',
    pathIN,
    '-out',
    pathOUT,
    '-nodes'
  ]
  var delTempPWFiles = []
  helper.createPasswordFile({ 'cipher': '', 'password': password, 'passType': 'in' }, params, delTempPWFiles[delTempPWFiles.length])
  helper.createPasswordFile({ 'cipher': '', 'password': password, 'passType': 'out' }, params, delTempPWFiles[delTempPWFiles.length])
  openssl.spawnWrapper(params, false, function (error, code) {
    function done (error) {
      if (error) {
        callback(error)
      } else {
        callback(null, code === 0)
      }
    }
    helper.deleteTempFiles(delTempPWFiles, function (fsErr) {
      done(error || fsErr)
    })
  })
}

//Information Exposure
function checkPkcs12 (bufferOrPath, passphrase, callback) {
  if (!callback && typeof passphrase === 'function') {
    callback = passphrase
    passphrase = ''
  }

  var tmpfiles = []
  var delTempPWFiles = []
  var args = ['pkcs12', '-info', '-in', bufferOrPath, '-noout', '-maciter', '-nodes']

  helper.createPasswordFile({ 'cipher': '', 'password': passphrase, 'passType': 'in' }, args, delTempPWFiles[delTempPWFiles.length])

  if (Buffer.isBuffer(bufferOrPath)) {
    tmpfiles = [bufferOrPath]
    args[3] = '--TMPFILE--'
  }

  openssl.spawnWrapper(args, tmpfiles, function (sslErr, code, stdout, stderr) {
    function done (err) {
      if (err) {
        return callback(err)
      }
      callback(null, (/MAC verified OK/im.test(stderr) || (!(/MAC verified OK/im.test(stderr)) && !(/Mac verify error/im.test(stderr)))))
    }
    helper.deleteTempFiles(delTempPWFiles, function (fsErr) {
      done(sslErr || fsErr)
    })
  })
}

//Cross-site Scripting (XSS)
function name3116( i, option ) {
                var item = this.items[option.idx];
                var matches = compare( option.textContent.trim().toLowerCase(), string );

                if ( matches && !option.disabled ) {
                    results.push( { text: option.textContent, value: option.value } );
                    if ( live ) {
                        appendItem( item, f, this.customOption );
                        util.removeClass( item, "excluded" );

                        // Underline the matching results
                        if ( !this.customOption ) {
                            item.innerHTML = match( string, option );
                        }
                    }
                } else if ( live ) {
                    util.addClass( item, "excluded" );
                }
            }

//Prototype Poisoning
async function name3117(value, definition) {

    if (!value &&
        definition.encoding === 'form') {

        return {};
    }

    Hoek.assert(typeof value === 'string', 'Invalid string');

    // Encodings: 'base64json', 'base64', 'form', 'iron', 'none'

    if (definition.encoding === 'iron') {
        return await Iron.unseal(value, definition.password, definition.iron || Iron.defaults);
    }

    if (definition.encoding === 'base64json') {
        const decoded = (Buffer.from(value, 'base64')).toString('binary');
        try {
            return JSON.parse(decoded);
        }
        catch (err) {
            throw Boom.badRequest('Invalid JSON payload');
        }
    }

    if (definition.encoding === 'base64') {
        return (Buffer.from(value, 'base64')).toString('binary');
    }

    // encoding: 'form'

    return Querystring.parse(value);
}

//Prototype Poisoning
async function name3118(value, definition) {

    if (!value &&
        definition.encoding === 'form') {

        return {};
    }

    Hoek.assert(typeof value === 'string', 'Invalid string');

    // Encodings: 'base64json', 'base64', 'form', 'iron', 'none'

    if (definition.encoding === 'iron') {
        return await Iron.unseal(value, definition.password, definition.iron || Iron.defaults);
    }

    if (definition.encoding === 'base64json') {
        const decoded = (Buffer.from(value, 'base64')).toString('binary');
        try {
            return JSON.parse(decoded);
        }
        catch (err) {
            throw Boom.badRequest('Invalid JSON payload');
        }
    }

    if (definition.encoding === 'base64') {
        return (Buffer.from(value, 'base64')).toString('binary');
    }

    // encoding: 'form'

    return Querystring.parse(value);
}

//Prototype Poisoning
async function name3119(value, definition) {

    if (!value &&
        definition.encoding === 'form') {

        return {};
    }

    Hoek.assert(typeof value === 'string', 'Invalid string');

    // Encodings: 'base64json', 'base64', 'form', 'iron', 'none'

    if (definition.encoding === 'iron') {
        return await Iron.unseal(value, definition.password, definition.iron || Iron.defaults);
    }

    if (definition.encoding === 'base64json') {
        const decoded = (Buffer.from(value, 'base64')).toString('binary');
        try {
            return JSON.parse(decoded);
        }
        catch (err) {
            throw Boom.badRequest('Invalid JSON payload');
        }
    }

    if (definition.encoding === 'base64') {
        return (Buffer.from(value, 'base64')).toString('binary');
    }

    // encoding: 'form'

    return Querystring.parse(value);
}

//Cross-site Scripting (XSS)
function name3120(tElement) {
        var startSym = $interpolate.startSymbol();
        var endSym = $interpolate.endSymbol();
        if (!(startSym === '{{' && endSym === '}}')) {
          var interpolatedHtml = tElement.html()
            .replace(/\{\{/g, startSym)
            .replace(/\}\}/g, endSym);
          tElement.html(interpolatedHtml);
        }
        return link;
      }

//Cross-site Scripting (XSS)
function name433 (h, { props, data, children }) {
    return h(
      props.footerTag,
      mergeData(data, {
        staticClass: 'card-footer',
        class: [
          props.footerClass,
          {
            [`bg-${props.footerBgVariant}`]: Boolean(props.footerBgVariant),
            [`border-${props.footerBorderVariant}`]: Boolean(props.footerBorderVariant),
            [`text-${props.footerTextVariant}`]: Boolean(props.footerTextVariant)
          }
        ]
      }),
      children || [h('div', { domProps: { innerHTML: props.footer } })]
    )
  }

//Cross-site Scripting (XSS)
function name434 (h, { props, data, children }) {
    return h(
      props.headerTag,
      mergeData(data, {
        staticClass: 'card-header',
        class: [
          props.headerClass,
          {
            [`bg-${props.headerBgVariant}`]: Boolean(props.headerBgVariant),
            [`border-${props.headerBorderVariant}`]: Boolean(props.headerBorderVariant),
            [`text-${props.headerTextVariant}`]: Boolean(props.headerTextVariant)
          }
        ]
      }),
      children || [h('div', { domProps: { innerHTML: props.header } })]
    )
  }

//Cross-site Scripting (XSS)
function name435 (option, index) {
      return h('option', {
        key: `option_${index}_opt`,
        attrs: { disabled: Boolean(option.disabled) },
        domProps: { innerHTML: option.text, value: option.value }
      })
    }

//Cross-site Scripting (XSS)
function name436 (h) {
    let childNodes = h(false)
    if (this.$slots.default) {
      childNodes = this.$slots.default
    } else if (this.label) {
      childNodes = h('span', { domProps: { innerHTML: stripScripts(this.label) } })
    } else if (this.computedShowProgress) {
      childNodes = this.progress.toFixed(this.computedPrecision)
    } else if (this.computedShowValue) {
      childNodes = this.value.toFixed(this.computedPrecision)
    }
    return h(
      'div',
      {
        class: this.progressBarClasses,
        style: this.progressBarStyles,
        attrs: {
          role: 'progressbar',
          'aria-valuemin': '0',
          'aria-valuemax': this.computedMax.toString(),
          'aria-valuenow': this.value.toFixed(this.computedPrecision)
        }
      },
      [childNodes]
    )
  }

//Cross-site Scripting (XSS)
function arrowFunc14(option, idx) {
      const uid = `_BV_option_${idx}_`
      return h(
        this.is_RadioGroup ? 'b-form-radio' : 'b-form-checkbox',
        {
          key: uid,
          props: {
            id: this.safeId(uid),
            value: option.value,
            disabled: option.disabled || null
            // Do we need to do these, since radio's will know they are inside here?
            // name: this.groupName,
            // form: this.form || null,
            // required: Boolean(this.name && this.required),
          }
        },
        [h('span', { domProps: { innerHTML: option.text } })]
      )
    }

//Cross-site Scripting (XSS)
isLast => {
      return h(
        'li',
        {
          key: `elipsis-${isLast ? 'last' : 'first'}`,
          class: ['page-item', 'disabled', 'd-none', 'd-sm-flex'],
          attrs: { role: 'separator' }
        },
        [
          this.$slots['ellipsis-text'] ||
            h('span', {
              class: ['page-link'],
              domProps: { innerHTML: stripScripts(this.ellipsisText) }
            })
        ]
      )
    }

//Cryptographic Backdoor
function name3121(max) {
	// gives a number between 0 (inclusive) and max (exclusive)
	return crypto.randomBytes(1)[0] % max;
}

//Regular Expression Denial of Service (ReDoS)
function findIndexes(code, identifiers) {
    const indexes = []

    if (identifiers.length === 0) {
      return indexes
    }

    const pattern = new RegExp("\\b(?:" + identifiers.join("|") + ")\\b", "g")

    let match

    while ((match = pattern.exec(code))) {
      const { index } = match

      // Make sure the match isn't preceded by a `.` character, since that
      // probably means the identifier is a property access rather than a
      // variable reference.
      if (index === 0 ||
          code.charCodeAt(index - 1) !== DOT) {
        indexes.push(index)
      }
    }

    return indexes
  }

//Regular Expression Denial of Service (ReDoS)
function init() {
  const {
    DOT
  } = CHAR_CODE

  function findIndexes(code, identifiers) {
    const indexes = []

    if (identifiers.length === 0) {
      return indexes
    }

    const pattern = new RegExp("\\b(?:" + identifiers.join("|") + ")\\b", "g")

    let match

    while ((match = pattern.exec(code))) {
      const { index } = match

      // Make sure the match isn't preceded by a `.` character, since that
      // probably means the identifier is a property access rather than a
      // variable reference.
      if (index === 0 ||
          code.charCodeAt(index - 1) !== DOT) {
        indexes.push(index)
      }
    }

    return indexes
  }

  return findIndexes
}

//Cross-site Scripting (XSS)
function name3122(html, allowed) {
  if (!html) {
    return '';
  }

  if (typeof html === 'number') {
    return html;
  }

  const whitelist = ((`${allowed || ''}`)
    .toLowerCase()
    .match(/<[a-z][a-z0-9]*>/g) || [])
    .join(''); // making sure the allowed arg is a string containing only tags in lowercase (<a><b><c>)

  const tags = /<\/?([a-z][a-z0-9]*)\b[^>]*>/gi;
  const commentsAndPhpTags = /<!--[\s\S]*?-->|<\?(?:php)?[\s\S]*?\?>/gi;

  return html.replace(commentsAndPhpTags, '')
    .replace(tags, ($0, $1) => whitelist.indexOf('<' + $1.toLowerCase() + '>') > -1 ? $0 : ''); //eslint-disable-line
}

//Cross-site Scripting (XSS)
async(request, response) => {
  if (isRestricted(request.params.url)) {
    response.status(403).send('Render request forbidden, domain excluded');
    return;
  }

  try {
    const start = now();
    const result = await renderer.serialize(request.params.url, request.query, config);
    response.status(result.status).send(result.body);
    track('render', now() - start);
  } catch (err) {
    let message = `Cannot render ${request.params.url}`;
    if (err && err.message)
      message += ` - "${err.message}"`;
    response.status(400).send(message);
  }
}

//Cross-site Scripting (XSS)
async(request, response) => {
  if (isRestricted(request.params.url)) {
    response.status(403).send('Render request forbidden, domain excluded');
    return;
  }

  try {
    const start = now();
    const result = await renderer.captureScreenshot(request.params.url, request.query, config).catch((err) => console.error(err));
    const img = new Buffer(result, 'base64');
    response.set({
      'Content-Type': 'image/jpeg',
      'Content-Length': img.length
    });
    response.end(img);
    track('screenshot', now() - start);
  } catch (err) {
    let message = `Cannot render ${request.params.url}`;
    if (err && err.message)
      message += ` - "${err.message}"`;
    response.status(400).send(message);
  }
}

//Prototype Pollution
function name3123(path, o) {
  var parts = typeof path === 'string' ?
    path.split('.') :
    path;

  if (!Array.isArray(parts)) {
    throw new TypeError('Invalid `path`. Must be either string or array');
  }

  var len = parts.length;
  var cur = o;
  for (var i = 0; i < len; ++i) {
    if (cur == null || typeof cur !== 'object' || !(parts[i] in cur)) {
      return false;
    }
    // Disallow any updates to __proto__.
    if (parts[i] === '__proto__') {
      return false;
    }
    if (i === len - 1) {
      delete cur[parts[i]];
      return true;
    }
    cur = cur instanceof Map ? cur.get(parts[i]) : cur[parts[i]];
  }

  return true;
}

//Arbitrary Command Execution
function name3124(name) {
    {
      // for now we ignore sense_version. might add it in the api name later
      let api = require('./' + name);
      result[name] = api.asJson();
    }
  }

//Arbitrary Command Execution
function name3125(sense_version, apis, reply) {
  let result = {};
  _.each(apis, function (name) {
    {
      // for now we ignore sense_version. might add it in the api name later
      let api = require('./' + name);
      result[name] = api.asJson();
    }
  });

  return reply(result).type("application/json");
}

//Arbitrary Code Injection
function compile (format) {
  if (typeof format !== 'string') {
    throw new TypeError('argument format must be a string')
  }

  var fmt = format.replace(/"/g, '\\"')
  var js = '  "use strict"\n  return "' + fmt.replace(/:([-\w]{2,})(?:\[([^\]]+)\])?/g, function (_, name, arg) {
    var tokenArguments = 'req, res'
    var tokenFunction = 'tokens[' + String(JSON.stringify(name)) + ']'

    if (arg !== undefined) {
      tokenArguments += ', ' + String(JSON.stringify(arg))
    }

    return '" +\n    (' + tokenFunction + '(' + tokenArguments + ') || "-") + "'
  }) + '"'

  // eslint-disable-next-line no-new-func
  return new Function('tokens, req, res', js)
}

//Prototype  Pollution
function i(e,n,i){var o=i[0],u=i.length;if(e||s(o)!=="object")o={};for(var a=0;a<u;++a){var f=i[a],l=s(f);if(l!=="object")continue;for(var c in f){var h=e?t.clone(f[c]):f[c];if(n){o[c]=r(o[c],h)}else{o[c]=h}}}return o}

//Prototype  Pollution
function name3126(e){function r(e,t){if(s(e)!=="object")return t;for(var n in t){if(s(e[n])==="object"&&s(t[n])==="object"){e[n]=r(e[n],t[n])}else{e[n]=t[n]}}return e}function i(e,n,i){var o=i[0],u=i.length;if(e||s(o)!=="object")o={};for(var a=0;a<u;++a){var f=i[a],l=s(f);if(l!=="object")continue;for(var c in f){var h=e?t.clone(f[c]):f[c];if(n){o[c]=r(o[c],h)}else{o[c]=h}}}return o}function s(e){return{}.toString.call(e).slice(8,-1).toLowerCase()}var t=function(e){return i(e===true,false,arguments)},n="merge";t.recursive=function(e){return i(e===true,true,arguments)};t.clone=function(e){var n=e,r=s(e),i,o;if(r==="array"){n=[];o=e.length;for(i=0;i<o;++i)n[i]=t.clone(e[i])}else if(r==="object"){n={};for(i in e)n[i]=t.clone(e[i])}return n};if(e){module.exports=t}else{window[n]=t}}

//Arbitrary Command Injection
function block(callback) {
        cmd = scope.command(opts, range);

        if (opts.verbose)
          console.log(`Running: ${cmd}`);

        const report = [];

        const execute = proc(cmd, (err, stdout, stderr) => {
          if (err)
            return reporting.reports(opts, err, callback);
        });

        execute.stderr.on('data', (chunk) => {
          /* Silently discard stderr messages to not interupt scans */
        });

        execute.stdout.on('data', (chunk) => {
          report.push(chunk);
        });

        execute.stdout.on('end', () => {
          if (report.length > 0)
            return reporting.reports(opts, report, callback);
        });
      }

//Arbitrary Command Injection
function blocks(block) {

      const range = opts.range[block];
      funcs[range] = function block(callback) {
        cmd = scope.command(opts, range);

        if (opts.verbose)
          console.log(`Running: ${cmd}`);

        const report = [];

        const execute = proc(cmd, (err, stdout, stderr) => {
          if (err)
            return reporting.reports(opts, err, callback);
        });

        execute.stderr.on('data', (chunk) => {
          /* Silently discard stderr messages to not interupt scans */
        });

        execute.stdout.on('data', (chunk) => {
          report.push(chunk);
        });

        execute.stdout.on('end', () => {
          if (report.length > 0)
            return reporting.reports(opts, report, callback);
        });
      };
    }

//Denial of Service (DoS)
function arrowFunc15(fieldName, stream, filename, encoding, mimetype) {
      if (!map)
        return reject(
          new FilesBeforeMapUploadError(
            `Misordered multipart fields; files should follow “map” (${SPEC_URL}).`,
            400
          )
        )

      if (map.has(fieldName))
        // File is expected.
        map.get(fieldName).resolve({
          stream,
          filename,
          mimetype,
          encoding
        })
      // Discard the unexpected file.
      else stream.resume()
    }

//Denial of Service (DoS)
function arrowFunc16() {
      if (map)
        for (const upload of map.values())
          if (!upload.file)
            upload.reject(
              new UploadPromiseDisconnectUploadError(
                'Request disconnected before file upload stream parsing.'
              )
            )
          else if (!upload.done) {
            upload.file.stream.truncated = true
            upload.file.stream.emit(
              'error',
              new FileStreamDisconnectUploadError(
                'Request disconnected during file upload stream parsing.'
              )
            )
          }
    }

//Denial of Service (DoS)
function arrowFunc17(fieldName, stream, filename, encoding, mimetype) {
      if (!map)
        return reject(
          new FilesBeforeMapUploadError(
            `Misordered multipart fields; files should follow “map” (${SPEC_URL}).`,
            400
          )
        )

      if (map.has(fieldName))
        // File is expected.
        map.get(fieldName).resolve({
          stream,
          filename,
          mimetype,
          encoding
        })
      // Discard the unexpected file.
      else stream.resume()
    }

//Denial of Service (DoS)
function arrowFunc18() {
      request.unpipe(parser)
      request.resume()

      if (map)
        for (const upload of map.values())
          if (!upload.file)
            upload.reject(createError(400, 'File missing in the request.'))
    }

//Denial of Service (DoS)
function name437 () {
      request.unpipe(parser)
      request.resume()

      if (map)
        for (const upload of map.values())
          if (!upload.file)
            upload.reject(createError(400, 'File missing in the request.'))
    }

//Denial of Service (DoS)
function name3127(t,e,n,r){void 0===n&&(n=!1);var i={before:e,after:t,inc:n};if(r)return this._iter(new Y("between",i,r));var o=this._cacheGet("between",i);return!1===o&&(o=this._iter(new x("between",i)),this._cacheAdd("between",o,i)),o}

//Denial of Service (DoS)
function name3128(t,e){void 0===e&&(e=!1);var n={dt:t,inc:e},r=this._cacheGet("before",n);return!1===r&&(r=this._iter(new x("before",n)),this._cacheAdd("before",r,n)),r}

//Denial of Service (DoS)
function name3129(t,e){void 0===e&&(e=!1);var n={dt:t,inc:e},r=this._cacheGet("after",n);return!1===r&&(r=this._iter(new x("after",n)),this._cacheAdd("after",r,n)),r}

//Information Exposure
async function name438 (options = {}) {
    await new Promise(async resolve => {
      if (!options.https) {
        this.server = http.createServer();
      } else if (typeof options.https === 'boolean') {
        this.server = https.createServer(generateCertificate(options));
      } else {
        this.server = https.createServer(await getCertificate(options.https));
      }

      this.wss = new WebSocket.Server({server: this.server});
      this.server.listen(options.hmrPort, resolve);
    });

    this.wss.on('connection', ws => {
      ws.onerror = this.handleSocketError;
      if (this.unresolvedError) {
        ws.send(JSON.stringify(this.unresolvedError));
      }
    });

    this.wss.on('error', this.handleSocketError);

    return this.wss._server.address().port;
  }

//Information Exposure
async function  start(options = {}) {
    await new Promise(async resolve => {
      if (!options.https) {
        this.server = http.createServer();
      } else if (typeof options.https === 'boolean') {
        this.server = https.createServer(generateCertificate(options));
      } else {
        this.server = https.createServer(await getCertificate(options.https));
      }

      this.wss = new WebSocket.Server({server: this.server});
      this.server.listen(options.hmrPort, resolve);
    });

    this.wss.on('connection', ws => {
      ws.onerror = this.handleSocketError;
      if (this.unresolvedError) {
        ws.send(JSON.stringify(this.unresolvedError));
      }
    });

    this.wss.on('error', this.handleSocketError);

    return this.wss._server.address().port;
  }

//Denial of Service (DoS)
function name3130(...args) {
		const key = options.cacheKey(...args);

		if (cache.has(key)) {
			const c = cache.get(key);

			if (noMaxAge || Date.now() < c.maxAge) {
				return c.data;
			}

			cache.delete(key);
		}

		const ret = fn.call(this, ...args);

		setData(key, ret);

		if (isPromise(ret) && options.cachePromiseRejection === false) {
			// Remove rejected promises from cache unless `cachePromiseRejection` is  to `true`
			ret.catch(() => cache.delete(key));
		}

		return ret;
	}

//Denial of Service (DoS)
function arrowFunc19(fn, options) {
	options = Object.assign({
		cacheKey: defaultCacheKey,
		cache: new Map(),
		cachePromiseRejection: false
	}, options);

	const {cache} = options;
	const noMaxAge = typeof options.maxAge !== 'number';
	options.maxAge = options.maxAge || 0;

	const setData = (key, data) => {
		cache.set(key, {
			data,
			maxAge: Date.now() + options.maxAge
		});
	};

	const memoized = function (...args) {
		const key = options.cacheKey(...args);

		if (cache.has(key)) {
			const c = cache.get(key);

			if (noMaxAge || Date.now() < c.maxAge) {
				return c.data;
			}

			cache.delete(key);
		}

		const ret = fn.call(this, ...args);

		setData(key, ret);

		if (isPromise(ret) && options.cachePromiseRejection === false) {
			// Remove rejected promises from cache unless `cachePromiseRejection` is  to `true`
			ret.catch(() => cache.delete(key));
		}

		return ret;
	};

	mimicFn(memoized, fn);

	cacheStore.set(memoized, options.cache);

	return memoized;
}

//Regular Expression Denial of Service (ReDoS)
function replace (string, options) {
    if (typeof string !== 'string') {
      throw new Error('slugify: string argument expected')
    }

    options = (typeof options === 'string')
      ? {replacement: options}
      : options || {}

    var slug = string.split('')
      .reduce(function (result, ch) {
        return result + (charMap[ch] || ch)
          // allowed
          .replace(options.remove || /[^\w\s$*_+~.()'"!\-:@]/g, '')
      }, '')
      // trim leading/trailing spaces
      .replace(/^\s+|\s+$/g, '')
      // convert spaces
      .replace(/[-\s]+/g, options.replacement || '-')
      // remove trailing separator
      .replace('#{replacement}$', '')

    return options.lower ? slug.toLowerCase() : slug
  }

//Denial of Service (DoS)
function nameconstructor2 () {
    this.header = [] // An array of unfolded header lines
    this.headers = {} // An object that holds header key=value pairs
    this.bodystructure = ''
    this.childNodes = [] // If this is a multipart or message/rfc822 mime part, the value will be converted to array and hold all child nodes for this node
    this.raw = '' // Stores the raw content of this node

    this._state = 'HEADER' // Current state, always starts out with HEADER
    this._bodyBuffer = '' // Body buffer
    this._lineCount = 0 // Line counter bor the body part
    this._currentChild = false // Active child node (if available)
    this._lineRemainder = '' // Remainder string when dealing with base64 and qp values
    this._isMultipart = false // Indicates if this is a multipart node
    this._multipartBoundary = false // Stores boundary value for current multipart node
    this._isRfc822 = false // Indicates if this is a message/rfc822 node
  }

//Denial of Service (DoS)
function parse1 (chunk) {
  const root = new MimeNode()
  const lines = (typeof chunk === 'object' ? String.fromCharCode.apply(null, chunk) : chunk).split(/\r?\n/g)
  lines.forEach(line => root.writeLine(line))
  root.finalize()
  return root
}

//Regular Expression Denial of Service (ReDoS)
function unescapeHTML(str) {
  return makeString(str).replace(/\&([^;]+);/g, function(entity, entityCode) {
    var match;

    if (entityCode in htmlEntities) {
      return htmlEntities[entityCode];
    /*eslint no-cond-assign: 0*/
    } else if (match = entityCode.match(/^#x([\da-fA-F]+)$/)) {
      return String.fromCharCode(parseInt(match[1], 16));
    /*eslint no-cond-assign: 0*/
    } else if (match = entityCode.match(/^#(\d+)$/)) {
      return String.fromCharCode(~~match[1]);
    } else {
      return entity;
    }
  });
}

//Cross-site Scripting (XSS)
function name3131(txn, res, params) {
  var inputs = [];
  
  Object.keys(params).forEach(function (k) {
    inputs.push(input.replace('{NAME}', k).replace('{VALUE}', entities.encode(params[k])));
   });

  res.setHeader('Content-Type', 'text/html;charset=UTF-8');
  res.setHeader('Cache-Control', 'no-cache, no-store');
  res.setHeader('Pragma', 'no-cache');

  return res.end(html.replace('{ACTION}', entities.encode(txn.redirectURI)).replace('{INPUTS}', inputs.join('')));
}

//Arbitrary File Write via Archive Extraction (Zip Slip)
function name3132(entry) {
    if (entry.type == 'Directory') return;
    entry.pipe(Writer({
      path: path.join(opts.path,entry.path)
    }))
    .on('error',function(e) {
      self.emit('error',e);
    });
  }

//Arbitrary File Write via Archive Extraction (Zip Slip)
function Extract (opts) {
  if (!(this instanceof Extract))
    return new Extract(opts);

  var self = this;

  Parse.call(self,opts);

  self.on('entry', function(entry) {
    if (entry.type == 'Directory') return;
    entry.pipe(Writer({
      path: path.join(opts.path,entry.path)
    }))
    .on('error',function(e) {
      self.emit('error',e);
    });
  });
}

//Arbitrary Command Injection
function name3133(err, stdout, stderr) {
        if (err) {
          return reject({
            message: "Failed to combine images",
            error: err,
            stdout: stdout,
            stderr: stderr
          });
        }
        exec("rm "+imagePaths.join(' ')); //cleanUp
        return resolve(pdfImage.getOutputImagePathForFile());
      }

//Arbitrary Command Injection
function name3134(resolve, reject) {
      exec(combineCommand, function (err, stdout, stderr) {
        if (err) {
          return reject({
            message: "Failed to combine images",
            error: err,
            stdout: stdout,
            stderr: stderr
          });
        }
        exec("rm "+imagePaths.join(' ')); //cleanUp
        return resolve(pdfImage.getOutputImagePathForFile());
      });
    }

//Arbitrary Command Injection
function name3135(imagePaths) {
    var pdfImage = this;
    var combineCommand = pdfImage.constructCombineCommandForFile(imagePaths);
    return new Promise(function (resolve, reject) {
      exec(combineCommand, function (err, stdout, stderr) {
        if (err) {
          return reject({
            message: "Failed to combine images",
            error: err,
            stdout: stdout,
            stderr: stderr
          });
        }
        exec("rm "+imagePaths.join(' ')); //cleanUp
        return resolve(pdfImage.getOutputImagePathForFile());
      });
    });
  }

//Uninitialized Memory Exposure
function name3136(data) {
  if (!this.writable) {
    var err = new Error('stream not writable')
    err.code = 'EPIPE'
    this.emit('error', err)
    return false
  }
  if (this.fromEncoding) {
    if (Buffer.isBuffer(data)) data = data.toString()
    data = new Buffer(data, this.fromEncoding)
  }
  var string = this.decoder.write(data)
  if (string.length) this.emit('data', string)
  return !this.paused
}

//Arbitrary Command Injection
function name3137(iface, callback) {
    exec("cat /sys/class/net/" + iface + "/address", function (err, out) {
        if (err) {
            callback(err, null);
            return;
        }
        callback(null, out.trim().toLowerCase());
    });
}

//Arbitrary Command Injection
function name3138(iface, callback) {
    exec("ifconfig " + iface, function (err, out) {
        if (err) {
            callback(err, null);
            return;
        }
        var match = /[a-f0-9]{2}(:[a-f0-9]{2}){5}/.exec(out.toLowerCase());
        if (!match) {
            callback("did not find a mac address", null);
            return;
        }
        callback(null, match[0].toLowerCase());
    });
}

//Arbitrary Command Injection
function name3139(iface, callback) {
    exec("ipconfig /all", function (err, out) {
        if (err) {
            callback(err, null);
            return;
        }
        var match = new RegExp(escape(iface)).exec(out);
        if (!match) {
            callback("did not find interface in `ipconfig /all`", null);
            return;
        }
        out = out.substring(match.index + iface.length);
        match = /[A-Fa-f0-9]{2}(\-[A-Fa-f0-9]{2}){5}/.exec(out);
        if (!match) {
            callback("did not find a mac address", null);
            return;
        }
        callback(null, match[0].toLowerCase().replace(/\-/g, ':'));
    });
}

//Uninitialized Memory Exposure
function name3140(afterSize) {
  if (this._size >= afterSize) {
    return;
  }
  var old = this._size;
  this._size = afterSize * 2;
  this._limit = this._size;
  debug('allocate new Buffer: from %d to %d bytes', old, this._size);
  var bytes;
  if (Buffer.allocUnsafe) {
    bytes = Buffer.allocUnsafe(this._size);
  } else {
    bytes = new Buffer(this._size);
  }
  this._bytes.copy(bytes, 0);
  this._bytes = bytes;
}

//Directory Traversal
function name3141(req, pathname) {
    pathname = decodeURI(pathname);
    // jumping to parent directories is not allowed
    if (pathname.indexOf('../') >= 0) {
      return RSVP.resolve(null);
    }

    var result = {};
    var foundPath;
    var fullPathnames = publicPaths.map(function(p) {
      return pathjoin(cwd, p, pathname);
    });

    return multiStat(fullPathnames).then(function(stat) {
      foundPath = stat.path;
      result.modified = stat.mtime.getTime();
      result.size = stat.size;
      return _fetchEtag(stat.path, stat);
    }).then(function(etag) {
      result.etag = etag;
      result.stream = fs.createReadStream(foundPath);
      return result;
    }).catch(function name3142(err) {
      if (err.code === 'ENOENT' || err.code === 'ENOTDIR' || err.code === 'EISDIR') {
        return null;
      }
      return RSVP.reject(err);
    });
  }

//Regular Expression Denial of Service (ReDoS)
function name3143(req, res) {

    var _url  = url.parse(req.url);

    var dest  = _url.hostname;
    var port  = _url.port || 80;
    var host  = '127.0.0.1';

    var target;
    if(proxy_host === '<ANY>' || proxy_host === dest) {

      target = {
        host: host,
        port: port
      };

      var urlmatch = req.url.match(/http:\/\/[^/]*:?[0-9]*(\/.*)$/);

      if(urlmatch) {
        req.url = urlmatch[1];
      } else {
        req.url = '/';
      }

    } else {
      target = {
        host: dest,
        port: port
      };
    }

    proxy.web(req, res, {target: target});

  }

//Cross-site Scripting (XSS)
function arrowFunc20(name, current) {
        const Info = CurrentInfo;
        const link = Info.link;
        const PREFIX = CloudCmd.PREFIX;
        const dir = PREFIX + FS + Info.dirPath;
        
        link.title      = name;
        link.innerHTML  = Entity.encode(name);
        link.href       = dir + name;
        
        current.setAttribute('data-name', 'js-file-' + name);
        
        return link;
    }

//Cross-site Scripting (XSS)
function nameee(file) {
        const link = prefix + FS + path + file.name;
        
        const type = getType(file.size);
        const size = getSize(file.size);
        
        const date = file.date || '--.--.----';
        const owner = file.owner || 'root';
        const mode = file.mode;
        
        const linkResult = rendy(templateLink, {
            link,
            title: file.name,
            name: Entity.encode(file.name),
            attribute: getAttribute(file.size)
        });
        
        const dataName = 'data-name="js-file-' + file.name + '" ';
        const attribute = 'draggable="true" ' + dataName;
        
        return rendy(templateFile, {
            tag: 'li',
            attribute,
            className: '',
            type,
            name: linkResult,
            size,
            date,
            owner,
            mode,
        });
    }

//Prototype Override
function querystring(query) {
  var parser = /([^=?&]+)=?([^&]*)/g
    , result = {}
    , part;

  //
  // Little nifty parsing hack, leverage the fact that RegExp.exec increments
  // the lastIndex property so we can continue executing this loop until we've
  // parsed all results.
  //
  for (;
    part = parser.exec(query);
    result[decode(part[1])] = decode(part[2])
  );

  return result;
}

//Prototype Pollution
function cloneSpecificValue(val) {
	if (val instanceof Buffer) {
		var x = new Buffer(val.length);
		val.copy(x);
		return x;
	} else if (val instanceof Date) {
		return new Date(val.getTime());
	} else if (val instanceof RegExp) {
		return new RegExp(val);
	} else {
		throw new Error('Unexpected situation');
	}
}

//Insecure Credential Comparison
function nativeTimingSafeEqual1(a, b) {
    var strA = String(a);
    var strB = String(b);
    
    var len = Math.max(Buffer.byteLength(strA), Buffer.byteLength(strB));
    
    var bufA = bufferAlloc(len, strA, 'utf8');
    var bufB = bufferAlloc(len, strB, 'utf8');
    
    return crypto.timingSafeEqual(bufA, bufB);
}

//Prototype Pollution
function arrowFunc21(merged, source, keys, mergeOpts) {
	keys.forEach(key => {
		if (key in merged) {
			merged[key] = merge(merged[key], source[key], mergeOpts);
		} else {
			merged[key] = clone(source[key]);
		}
	});

	return merged;
}

//Prototype Pollution
function cloneArray(array) {
	const result = array.slice(0, 0);

	getEnumerableOwnPropertyKeys(array).forEach(key => {
		result[key] = clone(array[key]);
	});

	return result;
}

//Arbitrary Command Injection
function name3144(error, stdout, stderr) {
        if (error || stderr || stdout === '' || stdout.indexOf( '/' ) === -1) {
          cp.exec('where ' + name, function (error, stdout, stderr) { //windows
            if (error || stderr || stdout === '' || stdout.indexOf('\\') === -1) {
              cp.exec('for %i in (' + name + '.exe) do @echo. %~$PATH:i', function (error, stdout, stderr) { //windows xp
                if (error || stderr || stdout === '' || stdout.indexOf('\\') === -1) {
                  return cb(new Error('Could not find ' + name + ' on your system'));
                }
                return cb(null, stdout);
              });
            } else {
              return cb(null, stdout);
            }
          });
        }
        else {
          return cb(null, stdout.split(' ')[1]);
        }
      }

//Regular Expression Denial of Service (ReDoS)
function arrowFunc22(text, data) {
    if (!data) {
        return text;
    }
    return text.replace(/\{\{\s*([^{}]+?)\s*\}\}/g, (fullMatch, term) => {
        if (term in data) {
            return data[term];
        }

        // Preserve old behavior: If parameter name not provided, don't replace it.
        return fullMatch;
    });
}

//Access Restriction Bypass
function name3145(er) {
      if (er) return cb(er)
      // Without prefix, nothing will ever work
      correctMkdir(this.prefix, cb)
    }

//Access Restriction Bypass
function name3146(er) {
    if (er) return cb(er)
    this.loadUid(function (er) {
      if (er) return cb(er)
      // Without prefix, nothing will ever work
      correctMkdir(this.prefix, cb)
    }.bind(this))
  }

//Access Restriction Bypass
function afterUser () {
    // globalconfig and globalignorefile defaults
    // need to respond to the 'prefix' setting up to this point.
    // Eg, `npm config get globalconfig --prefix ~/local` should
    // return `~/local/etc/npmrc`
    // annoying humans and their expectations!
    if (conf.get('prefix')) {
      var etc = path.resolve(conf.get('prefix'), 'etc')
      correctMkdir(etc, function () {
        defaults.globalconfig = path.resolve(etc, 'npmrc')
        defaults.globalignorefile = path.resolve(etc, 'npmignore')
        afterUserContinuation()
      })
    } else {
      afterUserContinuation()
    }
  }

//Access Restriction Bypass
function name3147(cb) {
  this.setUser(function (er) {
    if (er) return cb(er)
    this.loadUid(function (er) {
      if (er) return cb(er)
      // Without prefix, nothing will ever work
      correctMkdir(this.prefix, cb)
    }.bind(this))
  }.bind(this))
}

//Access Restriction Bypass
function setUser (cb) {
  var defaultConf = this.root
  assert(defaultConf !== Object.prototype)

  // If global, leave it as-is.
  // If not global, then  the user to the owner of the prefix folder.
  // Just set the default, so it can be overridden.
  if (this.get('global')) return cb()
  if (process.env.SUDO_UID) {
    defaultConf.user = +(process.env.SUDO_UID)
    return cb()
  }

  var prefix = path.resolve(this.get('prefix'))
  correctMkdir(prefix, function (er) {
    if (er) return cb(er)
    fs.stat(prefix, function (er, st) {
      defaultConf.user = st && st.uid
      return cb(er)
    })
  })
}

//Access Restriction Bypass
function name3148() {
    correctMkdir(self.where, iferr(cb, function () {
      var pkgs = {}
      self.args.forEach(function (pkg) {
        pkgs[pkg.name] = true
      })
      readPackageTree(self.where, function (ctx, kid) { return ctx.parent || pkgs[kid] }, iferr(cb, function (currentTree) {
        self.currentTree = currentTree
        return cb()
      }))
    }))
  }

//Access Restriction Bypass
function name3149(cb) {
  validate('F', arguments)
  log.silly('install', 'readGlobalPackageData')
  var self = this
  this.loadArgMetadata(iferr(cb, function () {
    correctMkdir(self.where, iferr(cb, function () {
      var pkgs = {}
      self.args.forEach(function (pkg) {
        pkgs[pkg.name] = true
      })
      readPackageTree(self.where, function (ctx, kid) { return ctx.parent || pkgs[kid] }, iferr(cb, function (currentTree) {
        self.currentTree = currentTree
        return cb()
      }))
    }))
  }))
}

//Access Restriction Bypass
function name3150(cb) {
  validate('F', arguments)
  log.silly('install', 'readLocalPackageData')
  var self = this
  correctMkdir(this.where, iferr(cb, function () {
    readPackageTree(self.where, iferr(cb, function (currentTree) {
      self.currentTree = currentTree
      self.currentTree.warnings = []
      if (currentTree.error && currentTree.error.code === 'EJSONPARSE') {
        return cb(currentTree.error)
      }
      if (!self.noPackageJsonOk && !currentTree.package) {
        log.error('install', "Couldn't read dependencies")
        var er = new Error("ENOENT, open '" + path.join(self.where, 'package.json') + "'")
        er.code = 'ENOPACKAGEJSON'
        er.errno = 34
        return cb(er)
      }
      if (!currentTree.package) currentTree.package = {}
      readShrinkwrap(currentTree, function (err) {
        if (err) {
          cb(err)
        } else {
          self.loadArgMetadata(cb)
        }
      })
    }))
  }))
}

//Access Restriction Bypass
function finishModule (bundler, child, stageTo, stageFrom) {
  // If we were the one's who bundled this module…
  if (child.fromBundle === bundler) {
    return correctMkdir(path.dirname(stageTo)).then(() => {
      return move(stageFrom, stageTo)
    })
  } else {
    return stat(stageFrom).then(() => gentlyRm(stageFrom), () => {})
  }
}

//Access Restriction Bypass
function arrowFunc23(modules) {
      if (!modules.length) return
      return correctMkdir(path.join(pkg.realpath, 'node_modules')).then(() => Bluebird.map(modules, (file) => {
        const from = path.join(delpath, 'node_modules', file)
        const to = path.join(pkg.realpath, 'node_modules', file)
        return move(from, to, moveOpts)
      }))
    }

//Access Restriction Bypass
function makeParentPath (dir) {
    return correctMkdir(path.dirname(dir))
  }

//Access Restriction Bypass
function restoreOldNodeModules () {
    if (!movedDestAway) return
    return readdir(path.join(delpath, 'node_modules')).catch(() => []).then((modules) => {
      if (!modules.length) return
      return correctMkdir(path.join(pkg.realpath, 'node_modules')).then(() => Bluebird.map(modules, (file) => {
        const from = path.join(delpath, 'node_modules', file)
        const to = path.join(pkg.realpath, 'node_modules', file)
        return move(from, to, moveOpts)
      }))
    })
  }

//Access Restriction Bypass
function name3151() {
      log.silly('move', 'make sure destination parent exists', path.resolve(to, '..'))
      correctMkdir(path.resolve(to, '..'), iferr(done, moveNodeModules(next)))
    }

//Access Restriction Bypass
function name3152() {
      correctMkdir(from, iferr(done, function () {
        log.silly('move', 'put source node_modules back', fromModules)
        move(tempFromModules, fromModules).then(next, done)
      }))
    }

//Access Restriction Bypass
function makeDestination (next) {
    return function () {
      log.silly('move', 'make sure destination parent exists', path.resolve(to, '..'))
      correctMkdir(path.resolve(to, '..'), iferr(done, moveNodeModules(next)))
    }
  }

//Access Restriction Bypass
function moveNodeModulesBack (next) {
    return function () {
      correctMkdir(from, iferr(done, function () {
        log.silly('move', 'put source node_modules back', fromModules)
        move(tempFromModules, fromModules).then(next, done)
      }))
    }
  }

//Access Restriction Bypass
function makeTarget (readdirEr, files) {
    if (readdirEr) return cleanup()
    if (!files.length) return cleanup()
    correctMkdir(path.join(pkg.path, 'node_modules'), function (mkdirEr) { moveModules(mkdirEr, files) })
  }

//Access Restriction Bypass
function fileCompletion (root, req, depth, cb) {
  if (typeof cb !== 'function') {
    cb = depth
    depth = Infinity
  }
  correctMkdir(root, function (er) {
    if (er) return cb(er)

    // can be either exactly the req, or a descendent
    var pattern = root + '/{' + req + ',' + req + '/**/*}'
    var opts = { mark: true, dot: true, maxDepth: depth }
    glob(pattern, opts, function (er, files) {
      if (er) return cb(er)
      return cb(null, (files || []).map(function (f) {
        return f.substr(root.length + 1).replace(/^\/|\/$/g, '')
      }))
    })
  })
}

//Regular Expression Denial of Service (ReDoS)
function parseFileHeader(index) {
    const headerPattern = /^(---|\+\+\+)\s+([\S ]*)(?:\t(.*?)\s*)?$/;
    const fileHeader = headerPattern.exec(diffstr[i]);
    if (fileHeader) {
      let keyPrefix = fileHeader[1] === '---' ? 'old' : 'new';
      let fileName = fileHeader[2].replace(/\\\\/g, '\\');
      if (/^".*"$/.test(fileName)) {
        fileName = fileName.substr(1, fileName.length - 2);
      }
      index[keyPrefix + 'FileName'] = fileName;
      index[keyPrefix + 'Header'] = fileHeader[3];

      i++;
    }
  }

//Regular Expression Denial of Service (ReDoS)
function isSafe1(userAgent) {
  var consecutive = 0
    , code = 0;

  for (var i = 0; i < userAgent.length; i++) {
    code = userAgent.charCodeAt(i);
    // numbers between 0 and 9
    if (code >= 48 && code <= 57) {
      consecutive++;
    } else {
      consecutive = 0;
    }

    if (consecutive >= 100) {
      return false;
    }
  }

  return true
}

//Regular Expression Denial of Service (ReDoS)
function mimeWordsEncode (data = '', mimeWordEncoding = 'Q', fromCharset = 'UTF-8') {
  const regex = /([^\s\u0080-\uFFFF]*[\u0080-\uFFFF]+[^\s\u0080-\uFFFF]*(?:\s+[^\s\u0080-\uFFFF]*[\u0080-\uFFFF]+[^\s\u0080-\uFFFF]*\s*)?)+(?=\s|$)/g
  return decode(convert(data, fromCharset)).replace(regex, match => match.length ? mimeWordEncode(match, mimeWordEncoding, fromCharset) : '')
}

//Cross-site Scripting (XSS)
function name3153(val) {
    this.hidePopover();
    this.textarea.val(val);
    this.body.get(0).innerHTML = val;
    this.formatter.format();
    this.formatter.decorate();
    this.util.reflow(this.body);
    this.inputManager.lastCaretPosition = null;
    return this.trigger('valuechanged');
  }

//Cross-site Scripting (XSS)
function name3154(val) {
    this.hidePopover();
    this.textarea.val(val);
    this.body.get(0).innerHTML = val;
    this.formatter.format();
    this.formatter.decorate();
    this.util.reflow(this.body);
    this.inputManager.lastCaretPosition = null;
    return this.trigger('valuechanged');
  }

//Cross-site Scripting (XSS)
function name3155(element, name) {
            element.name = name;

            // Workaround IE 6/7 issue
            // - https://github.com/SteveSanderson/knockout/issues/197
            // - http://www.matts411.com/post/setting_the_name_attribute_in_ie_dom/
            if (ieVersion <= 7) {
                try {
                    element.mergeAttributes(document.createElement("<input name='" + element.name + "'/>"), false);
                }
                catch(e) {} // For IE9 with doc mode "IE9 Standards" and browser mode "IE9 Compatibility View"
            }
        }

//Directory Traversal
function name3156(error, list) {
                    if (error) {
                        console.log(error);
                        res.end(error.toString())
                    }
                    var dirs = [];
                    var files = [];
                    list.forEach(function (val) {
                        var file = fs.lstatSync(path.join(targetPath, val));
                        if (file.isFile()) {
                            files.push(val)
                        } else if (file.isDirectory()) {
                            dirs.push(val);
                        }
                    });
                    res.writeHead(200);
                    res.write(utils.render(req.url, dirs, files));
                    res.end()
                }

//Regular Expression Denial of Service (ReDoS)
function username(cwd, verbose) {
  var repo = origin.sync(cwd);
  if (!repo && verbose) {
    console.error('  Can\'t calculate git-username, which probably means that\n  a git remote origin has not been defined.');
  }

  if (!repo) {
    return null;
  }

  var o = url.parse(repo);
  var path = o.path;

  if (path.length && path.charAt(0) === '/') {
    path = path.slice(1);
  } else {
    var match = /^git@\S+:(\S+)\//.exec(path);
    if (match && match[1]) {
      path = match[1];
    }
  }

  path = path.split('/')[0];
  return path;
}

//Regular Expression Denial of Service (ReDoS)
function name3157() {
      let t = this;
      //assume a contraction produces a word-word
      if (t.silent_term) {
        return true;
      }
      //no letters or numbers
      if (/[a-z|A-Z|0-9]/.test(t.text) === false) {
        return false;
      }
      //has letters, but with no vowels
      if (t.normal.length > 1 && hasLetter.test(t.normal) === true && hasVowel.test(t.normal) === false) {
        return false;
      }
      //has numbers but not a 'value'
      if (hasNumber.test(t.normal) === true) {
        //s4e
        if (/[a-z][0-9][a-z]/.test(t.normal) === true) {
          return false;
        }
        //ensure it looks like a 'value' eg '-$4,231.00'
        if (/^([$-])*?([0-9,\.])*?([s\$%])*?$/.test(t.normal) === false) {
          return false;
        }
      }
      return true;
    }

//Regular Expression Denial of Service (ReDoS)
function fixUrl(url, protocol) {
  if (!url) {
    return url;
  }

  protocol = protocol || 'http';

  // does it start with desired protocol?
  if ((new RegExp('^' + protocol + ':\/\/', 'i')).test(url)) {
    return url;
  }

  // if we have a different protocol, then invalidate
  if (/^\w+:\/\//i.test(url)) {
    return null;
  }

  // apply protocol to "abc.com/abc"
  if (/^(?:\w+\.\w{2,})+(?:\/.*|$)/.test(url)) {
    return protocol + '://' + url;
  }

  return null;
}

//Regular Expression Denial of Service (ReDoS)
function generateColumnString(column) {
  return /.+\(.*\)/.test(column)
    ? column // expression
    : template`"${column}"`; // single column
}

//Regular Expression Denial of Service (ReDoS)
function name3158() {
      var isInside = this.isInside('brace');
      var pos = this.position();
      var m = this.match(/^\{(,+(?:(\{,+\})*),*|,*(?:(\{,+\})*),+)\}/);
      if (!m) return;

      this.multiplier = true;
      var prev = this.prev();
      var val = m[0];

      if (isInside && prev.type === 'brace') {
        prev.text = prev.text || '';
        prev.text += val;
      }

      var node = pos(new Node({
        type: 'text',
        multiplier: 1,
        match: m,
        val: val
      }));

      return concatNodes.call(this, pos, node, prev, options);
    }

//Regular Expression Denial of Service (ReDoS)
function name3159(func) {
    if (func.name) {
      return func.name;
    }

    var matches = func.toString().match(/^\s*function\s*(\w*)\s*\(/) ||
      func.toString().match(/^\s*\[object\s*(\w*)Constructor\]/);

    return matches ? matches[1] : '<anonymous>';
  }

//Regular Expression Denial of Service (ReDoS)
function name3160(func) {
    if (func.name) {
      return func.name;
    }

    var matches = func.toString().match(/^\s*function\s*(\w*)\s*\(/) ||
      func.toString().match(/^\s*\[object\s*(\w*)Constructor\]/);

    return matches ? matches[1] : '<anonymous>';
  }

//Regular Expression Denial of Service (ReDoS)
function name3161() {
  'use strict';

  function validDataUrl(s) {
    return validDataUrl.regex.test(s);
  }
  validDataUrl.regex = /^\s*data:([a-z]+\/[a-z0-9-+.]+(;[a-z-]+=[a-z0-9-]+)?)?(;base64)?,([a-z0-9!$&',()*+;=\-._~:@\/?%\s]*?)\s*$/i;

  return validDataUrl;
}

//Regular Expression Denial of Service (ReDoS)
function name3162(path) {
        var last        = null,
            splitPathRe = /^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/;

        if (!path.match('.')) {
            return path;
        }

        path = splitPathRe.exec(path).slice(1);
        last = path[path.length - 1];

        return (last !== '') ? last : path[path.length - 2];
    }

//Regular Expression Denial of Service (ReDoS)
function name3163(a){var i=null,p=/^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/;if(!a.match(".")){return a}a=p.exec(a).slice(1);i=a[a.length-1];return i!==""?i:a[a.length-2]}

//Regular Expression Denial of Service (ReDoS)
function name3164(path) {
        var last        = null,
            splitPathRe = /^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/;

        if (!path.match('.')) {
            return path;
        }

        path = splitPathRe.exec(path).slice(1);
        last = path[path.length - 1];

        return (last !== '') ? last : path[path.length - 2];
    }

//Variables Overwrite
function name3165(name) {
   var Cacheman = require('cacheman');
   var _ = require('underscore');
   var options = {};
   // Get configuration
   config = sails.config.cacheman;
   if (config === undefined) {
        throw new Error('No configuration file found. Please add the configuration app/config/cacheman.js');
   }
   // if a valid driver is selected.
   if(_.indexOf(['memory', 'redis', 'mongo', 'file'], config.driver) < 0) {
        throw new Error("Invalid Driver selected. Please choose from ('memory', 'redis', 'mongo', 'file')");
   }

   var cache = new Cacheman(name, config[config.driver]);

   return cache;
}

//Arbitrary Command Execution
function name439 (res) {
        const branch = res.data.head.ref;
        execSync(
          `git fetch origin pull/${id}/head:${branch} && git checkout ${branch}`
        );
      }

//Arbitrary Command Execution
function name440 () {
    const url = execSync(`git config --get remote.origin.url`, {
      encoding: 'utf8'
    }).trim();

    return this.parsedGithubUrl(url);
  }

//Arbitrary Command Execution
function name441 (id) {
    return this.github.pullRequests
      .get({
        owner: this.owner,
        repo: this.repo,
        number: id
      })
      .then(res => {
        const branch = res.data.head.ref;
        execSync(
          `git fetch origin pull/${id}/head:${branch} && git checkout ${branch}`
        );
      })
      .catch(err => {
        console.log('Error: Could not find the specified pull request.');
      });
  }

//Arbitrary Command Execution
function nameinit() {
    const url = execSync(`git config --get remote.origin.url`, {
      encoding: 'utf8'
    }).trim();

    return this.parsedGithubUrl(url);
  }

//Arbitrary Command Execution
function namefetch(id) {
    return this.github.pullRequests
      .get({
        owner: this.owner,
        repo: this.repo,
        number: id
      })
      .then(res => {
        const branch = res.data.head.ref;
        execSync(
          `git fetch origin pull/${id}/head:${branch} && git checkout ${branch}`
        );
      })
      .catch(err => {
        console.log('Error: Could not find the specified pull request.');
      });
  }

//Insecure Credential Comparison
function nativeTimingSafeEqual2(a, b) {
    var strA = String(a);
    var strB = String(b);
    
    var len = Math.max(strA.length, strB.length);
    
    var bufA = bufferAlloc(len, strA, 'binary');
    var bufB = bufferAlloc(len, strB, 'binary');
    
    return crypto.timingSafeEqual(bufA, bufB);
}

//Arbitrary Code Execution
function isSafeMethod (object, method) {
  // test for plain functions defined on the object (instead of a method)
  if (hasOwnProperty(object, method)) {
    return isPlainObject(object);
  }
  else {
    // only allow methods defined on the prototype of this object
    // and not defined on the prototype of native Object
    // i.e. constructor, __defineGetter__, hasOwnProperty, etc. are not allowed
    // A few safe native methods are allowed: toString, valueOf, toLocaleString
    return (object &&
        hasOwnProperty(object.constructor.prototype, method) &&
        (!hasOwnProperty(Object.prototype, method) || hasOwnProperty(safeNativeMethods, method)));
  }
}

//Denial of Service (DoS)
function jsonBody (request, reply) {
  var body = ''
  var req = request.req
  req.on('error', onError)
  req.on('data', onData)
  req.on('end', onEnd)
  function onError (err) {
    reply.code(422).send(err)
  }
  function onData (chunk) {
    body += chunk
  }
  function onEnd () {
    try {
      request.body = JSON.parse(body)
    } catch (err) {
      reply.code(422).send(err)
      return
    }
    handler(reply)
  }
}

//Shell Command Injection
function arrowFunc24(err) {

        if (err && Net.isIP(host) === 0) {
            return callback(new Error('Invalid host'));
        }

        const command = (internals.isWin ? 'tracert -d ' : 'traceroute -q 1 -n ') + host;
        Child.exec(command, (err, stdout, stderr) => {

            if (err) {
                return callback(err);
            }

            const results = internals.parseOutput(stdout);
            return callback(null, results);
        });
    }

//Shell Command Injection
function name3166(host, callback) {


    Dns.lookup(host.toUpperCase(), (err) => {

        if (err && Net.isIP(host) === 0) {
            return callback(new Error('Invalid host'));
        }

        const command = (internals.isWin ? 'tracert -d ' : 'traceroute -q 1 -n ') + host;
        Child.exec(command, (err, stdout, stderr) => {

            if (err) {
                return callback(err);
            }

            const results = internals.parseOutput(stdout);
            return callback(null, results);
        });
    });
}

//Identity Spoofing
function arrowFunc25(err, remoteId) {
    if (err) {
      return callback(err)
    }

    state.id.remote = remoteId

    log('1.1 identify - %s - identified remote peer as %s', state.id.local.toB58String(), state.id.remote.toB58String())
    callback()
  }

//Identity Spoofing
function arrowFunc26(state, msg, callback) {
  log('1.1 identify')

  state.proposalEncoded.in = msg
  state.proposal.in = pbm.Propose.decode(msg)
  const pubkey = state.proposal.in.pubkey

  state.key.remote = crypto.keys.unmarshalPublicKey(pubkey)
  PeerId.createFromPubKey(pubkey.toString('base64'), (err, remoteId) => {
    if (err) {
      return callback(err)
    }

    state.id.remote = remoteId

    log('1.1 identify - %s - identified remote peer as %s', state.id.local.toB58String(), state.id.remote.toB58String())
    callback()
  })
}

//Cross-site Scripting (XSS)
function name3167(idx, temp, ftr, len){
					//keep the current loop. Tx to Adam Freidin
					var save_pos = ctxt.pos,
						save_item = ctxt.item,
						save_items = ctxt.items;
					ctxt.pos = temp.pos = idx;
					ctxt.item = temp.item = a[ idx ];
					ctxt.items = a;
					//if array, set a length property - filtered items
					if(typeof len !== 'undefined'){ ctxt.length = len; }
					//if filter directive
					if(typeof ftr === 'function' && ftr.call(ctxt.item, ctxt) === false){
						filtered++;
						return;
					}
					strs.push( inner.call(ctxt.item, ctxt ) );
					//restore the current loop
					ctxt.pos = save_pos;
					ctxt.item = save_item;
					ctxt.items = save_items;
				}

//Cross-site Scripting (XSS)
function name3168(ctxt){
			var data = ctxt.context || ctxt,
				v = ctxt[m[0]],
				i = 0,
				n,
				dm;

			if(v && typeof v.item !== 'undefined'){
				i += 1;
				if(m[i] === 'pos'){
					//allow pos to be kept by string. Tx to Adam Freidin
					return v.pos;
				}
				data = v.item;
			}
			n = m.length;

			while( i < n ){
				if(!data){break;}
				dm = data[ m[i] ];
				//if it is a function call it
				data = typeof dm === 'function' ? dm.call( data ) : dm;
				i++;
			}

			return !data && data !== 0 ? '':data;
		}

//Insecure Randomness
function name3169() {
  var _global = this;

  var mathRNG, whatwgRNG;

  // NOTE: Math.random() does not guarantee "cryptographic quality"
  mathRNG = function name3170(size) {
    var bytes = new Buffer(size);
    var r;

    for (var i = 0, r; i < size; i++) {
      if ((i & 0x03) == 0) r = Math.random() * 0x100000000;
      bytes[i] = r >>> ((i & 0x03) << 3) & 0xff;
    }

    return bytes;
  }

  if (_global.crypto && crypto.getRandomValues) {
    whatwgRNG = function name3171(size) {
      var bytes = new Buffer(size); //in browserify, this is an extended Uint8Array
      crypto.getRandomValues(bytes);
      return bytes;
    }
  }

  module.exports = whatwgRNG || mathRNG;

}

//Denial of Service (DoS)
function arrowFunc27(param) {
      const parts = param.trim().split('=');
      const key = parts[0];
      var value = parts[1];

      if (value === undefined) {
        value = true;
      } else {
        // unquote value
        if (value[0] === '"') {
          value = value.slice(1);
        }
        if (value[value.length - 1] === '"') {
          value = value.slice(0, value.length - 1);
        }
      }
      (parsedParams[key] = parsedParams[key] || []).push(value);
    }

//Denial of Service (DoS)
function arrowFunc28(v) {
    const params = v.split(';');
    const token = params.shift().trim();
    const paramsList = extensions[token] = extensions[token] || [];
    const parsedParams = {};

    params.forEach((param) => {
      const parts = param.trim().split('=');
      const key = parts[0];
      var value = parts[1];

      if (value === undefined) {
        value = true;
      } else {
        // unquote value
        if (value[0] === '"') {
          value = value.slice(1);
        }
        if (value[value.length - 1] === '"') {
          value = value.slice(0, value.length - 1);
        }
      }
      (parsedParams[key] = parsedParams[key] || []).push(value);
    });

    paramsList.push(parsedParams);
  }

//Denial of Service (DoS)
function name442 (value) {
  value = value || '';

  const extensions = {};

  value.split(',').forEach((v) => {
    const params = v.split(';');
    const token = params.shift().trim();
    const paramsList = extensions[token] = extensions[token] || [];
    const parsedParams = {};

    params.forEach((param) => {
      const parts = param.trim().split('=');
      const key = parts[0];
      var value = parts[1];

      if (value === undefined) {
        value = true;
      } else {
        // unquote value
        if (value[0] === '"') {
          value = value.slice(1);
        }
        if (value[value.length - 1] === '"') {
          value = value.slice(0, value.length - 1);
        }
      }
      (parsedParams[key] = parsedParams[key] || []).push(value);
    });

    paramsList.push(parsedParams);
  });

  return extensions;
}

//Cross-site Scripting (XSS)
function name443 () {
		// TODO: victoriafrench - is this the correct way to do this? the object
		// should be creating a default md where one does not exist imo.

		const innerHtml = (
			this.props.value !== undefined
			&& this.props.value.md !== undefined
		)
		? this.props.value.md.replace(/\n/g, '<br />')
		: '';

		return (
			`<FormInput
				dangerouslySetInnerHTML={{ __html: innerHtml }}
				multiline
				noedit
			/>`
		);
	}

//Open Redirect
function name3172(u) {
  var p = url.parse(u).pathname

  // Encoded dots are dots
  p = p.replace(/%2e/ig, '.')

  // encoded slashes are /
  p = p.replace(/%2f|%5c/ig, '/')

  // back slashes are slashes
  p = p.replace(/[\/\\]/g, '/')

  // Make sure it starts with a slash
  p = p.replace(/^\//, '/')

  if (p.match(/[\/\\]\.\.[\/\\]/)) {
    // traversal urls not ever even slightly allowed. clearly shenanigans
    // send a 403 on that noise, do not pass go, do not collect $200
    return 403
  }

  u = path.normalize(p).replace(/\\/g, '/')
  if (u.indexOf(this.url) !== 0) return false

  try {
    u = decodeURIComponent(u)
  }
  catch (e) {
    // if decodeURIComponent failed, we weren't given a valid URL to begin with.
    return false
  }

  // /a/b/c mounted on /path/to/z/d/x
  // /a/b/c/d --> /path/to/z/d/x/d
  u = u.substr(this.url.length)
  if (u.charAt(0) !== '/') u = '/' + u

  p = path.join(this.path, u)
  return p
}

//Credential Exposure
function arrowFunc29(env, key) {
      env[key] = process.env[key]
      return env
    }

//Credential Exposure
function name444 (env) {
  const PREFIX = /^AEGIR_/i
  const raw = Object.keys(process.env)
    .filter((key) => PREFIX.test(key))
    .reduce((env, key) => {
      env[key] = process.env[key]
      return env
    }, {
      NODE_ENV: process.env.NODE_ENV || env || 'development'
    })

  const stringifed = {
    'process.env': Object.keys(raw).reduce((env, key) => {
      env[key] = JSON.stringify(raw[key])
      return env
    }, {})
  }

  return {
    raw: raw,
    stringified: stringifed
  }
}

//Cross-site Scripting (XSS)
function name3173(embedder, options) {
  if (options.webPreferences == null) {
    options.webPreferences = {}
  }
  if (embedder.browserWindowOptions != null) {
    // Inherit the original options if it is a BrowserWindow.
    mergeOptions(options, embedder.browserWindowOptions)
  } else {
    // Or only inherit web-preferences if it is a webview.
    mergeOptions(options.webPreferences, embedder.getWebPreferences())
  }

  // Disable node integration on child window if disabled on parent window
  if (embedder.getWebPreferences().nodeIntegration === false) {
    options.webPreferences.nodeIntegration = false
  }

  // Enable context isolation on child window if enable on parent window
  if (embedder.getWebPreferences().contextIsolation === true) {
    options.webPreferences.contextIsolation = true
  }

  // Sets correct openerId here to give correct options to 'new-window' event handler
  options.webPreferences.openerId = embedder.id

  return options
}

//Denial of Service (DoS)
function name3174(message, title) {
    ipcRenderer.sendSync('ELECTRON_BROWSER_WINDOW_ALERT', message, title)
  }

//Denial of Service (DoS)
function name3175(message, title) {
    return ipcRenderer.sendSync('ELECTRON_BROWSER_WINDOW_CONFIRM', message, title)
  }

//Arbitrary Code Injection
(event, url, frameName,
                                      disposition, additionalFeatures,
                                      postData) => {
    const options = {
      show: true,
      width: 800,
      height: 600
    }
    ipcMain.emit('ELECTRON_GUEST_WINDOW_MANAGER_WINDOW_OPEN',
                 event, url, frameName, disposition,
                 options, additionalFeatures, postData)
  }

//Arbitrary Code Injection
(event, webContents, disposition,
                                            userGesture, left, top, width,
                                            height) => {
    let urlFrameName = v8Util.getHiddenValue(webContents, 'url-framename')
    if ((disposition !== 'foreground-tab' && disposition !== 'new-window') ||
        !urlFrameName) {
      return
    }

    let {url, frameName} = urlFrameName
    v8Util.deleteHiddenValue(webContents, 'url-framename')
    const options = {
      show: true,
      x: left,
      y: top,
      width: width || 800,
      height: height || 600,
      webContents: webContents
    }
    ipcMain.emit('ELECTRON_GUEST_WINDOW_MANAGER_WINDOW_OPEN', event, url, frameName, disposition, options)
  }

//Regular Expression Denial of Service (ReDoS)
function name3176(req, res) {
    // set appropriate Vary header
    vary(res, str)

    // multiple headers get joined with comma by node.js core
    return (req.headers[header] || '').split(/ *, */)
  }

//Regular Expression Denial of Service (ReDoS)
function createHeaderGetter (str) {
  var header = str.toLowerCase()

  return function (req, res) {
    // set appropriate Vary header
    vary(res, str)

    // multiple headers get joined with comma by node.js core
    return (req.headers[header] || '').split(/ *, */)
  }
}

//Regular Expression Denial of Service (ReDoS)
function name445 (path) {
    path = String(path);
    var last = path.replace(/.*[/\\]/, '').toLowerCase();
    var ext = last.replace(/.*\./, '').toLowerCase();

    var hasPath = last.length < path.length;
    var hasDot = ext.length < last.length - 1;

    return (hasDot || !hasPath) && this._types[ext] || null;
  }

//Regular Expression Denial of Service (ReDoS)
function namegetType(path) {
    path = String(path);
    var last = path.replace(/.*[/\\]/, '').toLowerCase();
    var ext = last.replace(/.*\./, '').toLowerCase();

    var hasPath = last.length < path.length;
    var hasDot = ext.length < last.length - 1;

    return (hasDot || !hasPath) && this._types[ext] || null;
  }

//Uninitialized Memory Exposure
function mergeBuffers(buffers) {
  var mergeBuffer  = new Buffer(options.bufferSize);
  var mergeBuffers = [];
  var offset       = 0;

  for (var i = 0; i < buffers.length; i++) {
    var buffer = buffers[i];

    var bytesRemaining = mergeBuffer.length - offset;
    if (buffer.length < bytesRemaining) {
      buffer.copy(mergeBuffer, offset);
      offset += buffer.length;
    } else {
      buffer.copy(mergeBuffer, offset, 0, bytesRemaining);
      mergeBuffers.push(mergeBuffer);

      mergeBuffer = new Buffer(options.bufferSize);
      buffer.copy(mergeBuffer, 0, bytesRemaining);
      offset = buffer.length - bytesRemaining;
    }
  }

  if (offset > 0) {
    mergeBuffers.push(mergeBuffer.slice(0, offset));
  }

  return mergeBuffers;
}

//Uninitialized Memory Exposure
function name3177(password, scramble) {
  if (!password) {
    return new Buffer(0);
  }

  // password must be in binary format, not utf8
  var stage1 = sha1((new Buffer(password, 'utf8')).toString('binary'));
  var stage2 = sha1(stage1);
  var stage3 = sha1(scramble.toString('binary') + stage2);
  return xor(stage3, stage1);
}

//Uninitialized Memory Exposure
function name3178(password) {
  var nr = [0x5030, 0x5735],
      add = 7,
      nr2 = [0x1234, 0x5671],
      result = new Buffer(8);

  if (typeof password === 'string'){
    password = new Buffer(password);
  }

  for (var i = 0; i < password.length; i++) {
    var c = password[i];
    if (c === 32 || c === 9) {
      // skip space in password
      continue;
    }

    // nr^= (((nr & 63)+add)*c)+ (nr << 8);
    // nr = xor(nr, add(mul(add(and(nr, 63), add), c), shl(nr, 8)))
    nr = this.xor32(nr, this.add32(this.mul32(this.add32(this.and32(nr, [0,63]), [0,add]), [0,c]), this.shl32(nr, 8)));

    // nr2+=(nr2 << 8) ^ nr;
    // nr2 = add(nr2, xor(shl(nr2, 8), nr))
    nr2 = this.add32(nr2, this.xor32(this.shl32(nr2, 8), nr));

    // add+=tmp;
    add += c;
  }

  this.int31Write(result, nr, 0);
  this.int31Write(result, nr2, 4);

  return result;
}

//Uninitialized Memory Exposure
function name3179(message, password) {
  var to = new Buffer(8),
      hashPass = this.hashPassword(password),
      hashMessage = this.hashPassword(message.slice(0, 8)),
      seed1 = this.int32Read(hashPass, 0) ^ this.int32Read(hashMessage, 0),
      seed2 = this.int32Read(hashPass, 4) ^ this.int32Read(hashMessage, 4),
      r = this.randomInit(seed1, seed2);

  for (var i = 0; i < 8; i++){
    to[i] = Math.floor(this.myRnd(r) * 31) + 64;
  }
  var extra = (Math.floor(this.myRnd(r) * 31));

  for (var i = 0; i < 8; i++){
    to[i] ^= extra;
  }

  return to;
}

//Uninitialized Memory Exposure
function xor(a, b) {
  a = new Buffer(a, 'binary');
  b = new Buffer(b, 'binary');
  var result = new Buffer(a.length);
  for (var i = 0; i < a.length; i++) {
    result[i] = (a[i] ^ b[i]);
  }
  return result;
}

//Uninitialized Memory Exposure
function toBuffer(parser) {
  if (!this._buffer) {
    this._buffer = new Buffer(0);
    this._offset = 0;
  }

  var buffer  = this._buffer;
  var length  = this._offset;
  var packets = Math.floor(length / MAX_PACKET_LENGTH) + 1;

  this._buffer = new Buffer(length + packets * 4);
  this._offset = 0;

  for (var packet = 0; packet < packets; packet++) {
    var isLast = (packet + 1 === packets);
    var packetLength = (isLast)
      ? length % MAX_PACKET_LENGTH
      : MAX_PACKET_LENGTH;

    var packetNumber = parser.incrementPacketNumber();

    this.writeUnsignedNumber(3, packetLength);
    this.writeUnsignedNumber(1, packetNumber);

    var start = packet * MAX_PACKET_LENGTH;
    var end   = start + packetLength;

    this.writeBuffer(buffer.slice(start, end));
  }

  return this._buffer;
}

//Uninitialized Memory Exposure
function _allocate(bytes) {
  if (!this._buffer) {
    this._buffer = new Buffer(Math.max(BUFFER_ALLOC_SIZE, bytes));
    this._offset = 0;
    return;
  }

  var bytesRemaining = this._buffer.length - this._offset;
  if (bytesRemaining >= bytes) {
    return;
  }

  var newSize   = this._buffer.length + Math.max(BUFFER_ALLOC_SIZE, bytes);
  var oldBuffer = this._buffer;

  this._buffer = new Buffer(newSize);
  oldBuffer.copy(this._buffer);
}

//Uninitialized Memory Exposure
function name3180(length) {
  var response = new Buffer(length);
  this._buffer.copy(response, 0, this._offset, this._offset + length);

  this._offset += length;
  return response;
}

//Uninitialized Memory Exposure
function _combineLongPacketBuffers() {
  if (!this._longPacketBuffers.size) {
    return;
  }

  // Calculate bytes
  var remainingBytes      = this._buffer.length - this._offset;
  var trailingPacketBytes = this._buffer.length - this._packetEnd;

  // Create buffer
  var buf    = null;
  var buffer = new Buffer(remainingBytes + this._longPacketBuffers.size);
  var offset = 0;

  // Copy long buffers
  while ((buf = this._longPacketBuffers.shift())) {
    offset += buf.copy(buffer, offset);
  }

  // Copy remaining bytes
  this._buffer.copy(buffer, offset, this._offset);

  this._buffer       = buffer;
  this._offset       = 0;
  this._packetEnd    = this._buffer.length - trailingPacketBytes;
  this._packetOffset = 0;
}

//Uninitialized Memory Exposure
function Parser(options) {
  options = options || {};

  this._supportBigNumbers = options.config && options.config.supportBigNumbers;
  this._buffer            = new Buffer(0);
  this._nextBuffers       = new BufferList();
  this._longPacketBuffers = new BufferList();
  this._offset            = 0;
  this._packetEnd         = null;
  this._packetHeader      = null;
  this._packetOffset      = null;
  this._onError           = options.onError || function(err) { throw err; };
  this._onPacket          = options.onPacket || function() {};
  this._nextPacketNumber  = 0;
  this._encoding          = 'utf-8';
  this._paused            = false;
}

//Uninitialized Memory Exposure
function name3181(writer) {
  if (this.protocol41) {
    writer.writeUnsignedNumber(4, this.clientFlags);
    writer.writeUnsignedNumber(4, this.maxPacketSize);
    writer.writeUnsignedNumber(1, this.charsetNumber);
    writer.writeFiller(23);
    writer.writeNullTerminatedString(this.user);
    writer.writeLengthCodedBuffer(this.scrambleBuff);
    writer.writeNullTerminatedString(this.database);
  } else {
    writer.writeUnsignedNumber(2, this.clientFlags);
    writer.writeUnsignedNumber(3, this.maxPacketSize);
    writer.writeNullTerminatedString(this.user);
    writer.writeBuffer(this.scrambleBuff);
    if (this.database && this.database.length) {
      writer.writeFiller(1);
      writer.writeBuffer(new Buffer(this.database));
    }
  }
}

//Uninitialized Memory Exposure
function name3182() {
  var buffer = new Buffer(this.scrambleBuff1.length +
                          (typeof this.scrambleBuff2 !== 'undefined' ? this.scrambleBuff2.length : 0));

  this.scrambleBuff1.copy(buffer);
  if (typeof this.scrambleBuff2 !== 'undefined') {
    this.scrambleBuff2.copy(buffer, this.scrambleBuff1.length);
  }

  return buffer;
}

//Uninitialized Memory Exposure
function name446 () {
    const api_key_base64 = new Buffer(this.options.api_key).toString('base64')
    return `Basic ${api_key_base64}`
  }

//Uninitialized Memory Exposure
function nameauth_header () {
    const api_key_base64 = new Buffer(this.options.api_key).toString('base64')
    return `Basic ${api_key_base64}`
  }

//Timing Attack
function verifyHMAC(parsedSignature, secret) {
    assert.object(parsedSignature, 'parsedHMAC');
    assert.string(secret, 'secret');

    var alg = parsedSignature.algorithm.match(/^HMAC-(\w+)/);
    if (!alg || alg.length !== 2)
      throw new TypeError('parsedSignature: unsupported algorithm ' +
                          parsedSignature.algorithm);

    var hmac = crypto.createHmac(alg[1].toUpperCase(), secret);
    hmac.update(parsedSignature.signingString);
    return (hmac.digest('base64') === parsedSignature.params.signature);
  }

//Uninitialized Memory Exposure
function name3183(data,meta){

    em.stats.requestedWrites++;
    // just got a write save the time between last write and this.
    var now = Date.now();
    writes.push(now); 

    // write events are emitted with an array of data from all of the writes combined into one.
    if(meta) em.data.push(meta);

    if(writes.length > windowSize) writes.shift();

    data = data instanceof Buffer ? data : new Buffer(data);
    bufLen += data.length;

    buf.push(data);

    if(em.shouldWrite()) em._write();

  }

//Cross-site Scripting (XSS)
function name3184(text) {
    var html = '';
    if(typeof text !== undefined) {
      if(typeof text.title !== undefined && text.title) {
        html += '<div class="header">' + text.title + '</div class="header">';
      }
      if(typeof text.content !== undefined && text.content) {
        html += '<div class="content">' + text.content + '</div>';
      }
    }
    return html;
  }

//Arbitrary Command Injection
function name3185(pid, options, done) {

    var cmd = 'ps -o pcpu,rss -p '

    if(os.platform() == 'aix')
      cmd = 'ps -o pcpu,rssize -p ' //this one could work on other platforms

    exec(cmd + pid, function(err, stdout, stderr) {
      if(err)
        return done(err, null)

      stdout = stdout.split(os.EOL)[1]
      stdout = stdout.replace(/^\s+/, '').replace(/\s\s+/g, ' ').split(' ')

      return done(null, {
        cpu: parseFloat(stdout[0].replace(',', '.')),
        memory: parseFloat(stdout[1]) * 1024
      })
    })
  }

//Uninitialized Memory Exposure
function name447 (addr, mask) {
  addr = ip.toBuffer(addr);
  mask = ip.toBuffer(mask);

  var result = new Buffer(Math.max(addr.length, mask.length));

  // Same protocol - do bitwise and
  if (addr.length === mask.length) {
    for (var i = 0; i < addr.length; i++) {
      result[i] = addr[i] & mask[i];
    }
  } else if (mask.length === 4) {
    // IPv6 address and IPv4 mask
    // (Mask low bits)
    for (var i = 0; i < mask.length; i++) {
      result[i] = addr[addr.length - 4  + i] & mask[i];
    }
  } else {
    // IPv6 mask and IPv4 addr
    for (var i = 0; i < result.length - 6; i++) {
      result[i] = 0;
    }

    // ::ffff:ipv4
    result[10] = 0xff;
    result[11] = 0xff;
    for (var i = 0; i < addr.length; i++) {
      result[i + 12] = addr[i] & mask[i + 12];
    }
  }

  return ip.toString(result);
}

//Cross-site Scripting (XSS)
function name3186(repo) {
    const adapter = this.adapter

    this.$view.find('.octotree_view_header')
      .html(
        '<div class="octotree_header_repo">' +
           '<a href="/' + repo.username + '">' + repo.username +'</a>'  +
           ' / ' +
           '<a data-pjax href="/' + repo.username + '/' + repo.reponame + '">' + repo.reponame +'</a>' +
         '</div>' +
         '<div class="octotree_header_branch">' +
           repo.branch +
         '</div>'
      )
      .on('click', 'a[data-pjax]', function (event) {
        event.preventDefault()
        adapter.selectFile($(this).attr('href') /* a.href always return absolute URL, don't want that */)
      })
  }

//Cross-site Scripting (XSS)
function _showHeader(repo) {
    const adapter = this.adapter

    this.$view.find('.octotree_view_header')
      .html(
        '<div class="octotree_header_repo">' +
           '<a href="/' + repo.username + '">' + repo.username +'</a>'  +
           ' / ' +
           '<a data-pjax href="/' + repo.username + '/' + repo.reponame + '">' + repo.reponame +'</a>' +
         '</div>' +
         '<div class="octotree_header_branch">' +
           repo.branch +
         '</div>'
      )
      .on('click', 'a[data-pjax]', function (event) {
        event.preventDefault()
        adapter.selectFile($(this).attr('href') /* a.href always return absolute URL, don't want that */)
      })
  }

//Cross-site Scripting (XSS)
function name3187 (item) {
        var path   = item.path
          , index  = path.lastIndexOf('/')
          , name   = path.substring(index + 1)
          , folder = folders[path.substring(0, index)]
          , url    = '/' + repo.username + '/' + repo.reponame + '/' + item.type + '/' + repo.branch + '/' + path

        folder.push(item)
        item.text   = name
        item.icon   = item.type
        if (item.type === 'tree') {
          folders[item.path] = item.children = []
          item.a_attr = { href: '#' }
        }
        else if (item.type === 'blob') {
          item.a_attr = { href: url }
        }
      }

//Cross-site Scripting (XSS)
function handleSource(req, res, next) {
    req.body.subscribed_url = req.body.location;
    req.body.subscribed_referrer = req.body.referrer;
    delete req.body.location;
    delete req.body.referrer;

    postlookup(req.body.subscribed_url)
        .then(function (result) {
            if (result && result.post) {
                req.body.post_id = result.post.id;
            }

            next();
        })
        .catch(function (err) {
            if (err instanceof errors.NotFoundError) {
                return next();
            }

            next(err);
        });
}

//Cross-site Scripting (XSS)
function name3188(template, data) {
    return !template ? '' : (FN[template] = FN[template] || new Function("_",
      "return '" + template
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r")
        .replace(/'/g, "\\'")
        .replace(/\{\s*(\w+)\s*\}/g, "' + (_.$1 === undefined || _.$1 === null ? '' : _.$1) + '") +
      "'"
    ))(data);
  }

//Cross-site Scripting (XSS)
function name448 () {

  // Precompiled templates (JavaScript functions)
  var FN = {};

  // Render a template with data
  $.render = function(template, data) {
    return !template ? '' : (FN[template] = FN[template] || new Function("_",
      "return '" + template
        .replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r")
        .replace(/'/g, "\\'")
        .replace(/\{\s*(\w+)\s*\}/g, "' + (_.$1 === undefined || _.$1 === null ? '' : _.$1) + '") +
      "'"
    ))(data);
  }

}

//Cross-site Scripting (XSS)
function name449 (value, key) {
    if (_.isString(value)) {
      parsed = _.unescape(value);
      try {
        parsed = JSON.parse(parsed);
      } catch (err) {}
      options[key] = parsed;
    }
  }

//Cross-site Scripting (XSS)
function name450 ($el) {
  var parsed,
    options = $el.data();

  _.each(options, function(value, key) {
    if (_.isString(value)) {
      parsed = _.unescape(value);
      try {
        parsed = JSON.parse(parsed);
      } catch (err) {}
      options[key] = parsed;
    }
  });

  return options;
}

//Information Exposure
function name451 (opts) {
  if(!opts) opts = {};
  var urlOpts;
  var self = this;
  
  urlOpts = {
    'response_type': 'code',
    'client_id': self.clientId,
    'client_secret': self.clientSecret,
    'redirect_uri': self.redirectUri
  }

  if(opts.display) {
    urlOpts.display = opts.display.toLowerCase();
  }

  if(opts.immediate) {
    urlOpts.immediate = opts.immediate;
  }

  if(opts.scope) {
    if(typeof opts.scope === 'object') {
      urlOpts.scope = opts.scope.join(' ');
    }
  }

  if(opts.state) {
    urlOpts.state = opts.state;
  }

  if(self.environment == 'sandbox') {
    return TEST_AUTH_ENDPOINT + '?' + qs.stringify(urlOpts);
  } else {
    return AUTH_ENDPOINT + '?' + qs.stringify(urlOpts);
  }
}

//Cross-site Scripting (XSS)
function displayCaptions() {

		if (this.tracks === undefined) {
			return;
		}

		var t = this,
		    track = t.selectedTrack,
		    i = void 0;

		if (track !== null && track.isLoaded) {
			i = t.searchTrackPosition(track.entries, t.media.currentTime);
			if (i > -1) {
				// Set the line before the timecode as a class so the cue can be targeted if needed
				t.captionsText.html(track.entries[i].text).attr('class', t.options.classPrefix + 'captions-text ' + (track.entries[i].identifier || ''));
				t.captions.show().height(0);
				return; // exit out if one is visible;
			}

			t.captions.hide();
		} else {
			t.captions.hide();
		}
	}

//Cross-site Scripting (XSS)
function name452 (){if(void 0!==this.tracks){var a=this,b=a.selectedTrack,c=void 0;if(null!==b&&b.isLoaded){if(c=a.searchTrackPosition(b.entries,a.media.currentTime),c>-1)return a.captionsText.html(b.entries[c].text).attr("class",a.options.classPrefix+"captions-text "+(b.entries[c].identifier||"")),void a.captions.show().height(0);a.captions.hide()}else a.captions.hide()}}

//Cross-site Scripting (XSS)
function displayCaptions1() {

		if (this.tracks === undefined) {
			return;
		}

		var t = this,
		    track = t.selectedTrack,
		    i = void 0;

		if (track !== null && track.isLoaded) {
			i = t.searchTrackPosition(track.entries, t.media.currentTime);
			if (i > -1) {
				// Set the line before the timecode as a class so the cue can be targeted if needed
				t.captionsText.html(track.entries[i].text).attr('class', t.options.classPrefix + 'captions-text ' + (track.entries[i].identifier || ''));
				t.captions.show().height(0);
				return; // exit out if one is visible;
			}

			t.captions.hide();
		} else {
			t.captions.hide();
		}
	}

//Cross-site Scripting (XSS)
function name453 (){if(void 0!==this.tracks){var a=this,b=a.selectedTrack,c=void 0;if(null!==b&&b.isLoaded){if(c=a.searchTrackPosition(b.entries,a.media.currentTime),c>-1)return a.captionsText.html(b.entries[c].text).attr("class",a.options.classPrefix+"captions-text "+(b.entries[c].identifier||"")),void a.captions.show().height(0);a.captions.hide()}else a.captions.hide()}}

//Cross-site Scripting (XSS)
function name3189()  {

		if (this.tracks === undefined) {
			return;
		}

		let
			t = this,
			track = t.selectedTrack,
			i
		;

		if (track !== null && track.isLoaded) {
			i = t.searchTrackPosition(track.entries, t.media.currentTime);
			if (i > -1) {
				// Set the line before the timecode as a class so the cue can be targeted if needed
				t.captionsText.html(track.entries[i].text)
				.attr('class', `${t.options.classPrefix}captions-text ${(track.entries[i].identifier || '')}`);
				t.captions.show().height(0);
				return; // exit out if one is visible;
			}

			t.captions.hide();
		} else {
			t.captions.hide();
		}
	}

//Cross-site Scripting (XSS)
function drawVideo(video) {
			if (video.paused || video.ended || _stop) {
				return false;
			}
			//nasty hack for FF webcam (Thanks to Julian Ćwirko, kontakt@redsunmedia.pl)
			try {
				_context.clearRect(0, 0, _w, _h);
				_context.drawImage(video, 0, 0, _w, _h);
			} catch(e) {

			}
			_drawTimeout = setTimeout(drawVideo, animation.duration, video);
			link.setIcon(_canvas);
		}

//Cross-site Request Forgery (CSRF)
function name3190() {
    if (!data) {
      con.end();
      return;
    }
    if (data === 'stop') {
      con.end();
      server.close();
      return;
    }
    var cwd, args, text;
    if (data.substring(0, 1) === '{') {
      var json = JSON.parse(data);
      cwd = json.cwd;
      args = json.args;
      text = json.text;
    } else {
      var parts = data.split(' ');
      cwd = parts[0];
      args = parts.slice(1);
    }
    try {
      con.write(linter(cwd, args, text));
    } catch (e) {
      con.write(e.toString() + '\n');
    }
    con.end();
  }

//Cross-site Request Forgery (CSRF)
function name3191(con) {
  var data = '';
  con.on('data', function (chunk) {
    data += chunk;
  });
  con.on('end', function () {
    if (!data) {
      con.end();
      return;
    }
    if (data === 'stop') {
      con.end();
      server.close();
      return;
    }
    var cwd, args, text;
    if (data.substring(0, 1) === '{') {
      var json = JSON.parse(data);
      cwd = json.cwd;
      args = json.args;
      text = json.text;
    } else {
      var parts = data.split(' ');
      cwd = parts[0];
      args = parts.slice(1);
    }
    try {
      con.write(linter(cwd, args, text));
    } catch (e) {
      con.write(e.toString() + '\n');
    }
    con.end();
  });
}

//Directory Traversal
function name3192(api, connection, next){
		var fileName = "";
		if((connection.params.fileName == null || typeof connection.params.fileName == "undefined") && connection.req != null){
			var parsedURL = api.url.parse(connection.req.url);
			var parts = parsedURL.pathname.split("/");
			
			parts.shift();
			if (connection.directModeAccess == true){ parts.shift(); }
			if (connection.requestMode == "api"){ parts.shift(); }
			
			for (var i in parts){
				if (fileName != ""){ fileName += "/"; }
				fileName += parts[i];
			}
		}else if(connection.req == null){
			// socket connection
			api.utils.requiredParamChecker(api, connection, ["fileName"]);
			if(connection.error === null){ fileName = connection.params.fileName; }
		}else{
			fileName = connection.params.fileName;
		}
		if(connection.error === null){
			fileName = api.configData.general.flatFileDirectory + fileName;
			api.fileServer.followFileToServe(api, fileName, connection, next);
		}
	}

//Directory Traversal
function requestListener(req, res) {
  var uri, file, data;

  current_url = req.url;

  uri = decodeURIComponent(url.parse(req.url).pathname);
  file = path.join(process.cwd(), uri);
  acceptEncoding = req.headers['accept-encoding'];
  data = routes.get(req.url);

  if (data) {
    sendReponse(res, data);
    return;
  }

  fs.exists(file, function (exists) {
    if (exists) {
      checkFile(res, file);

    } else {
      res.writeHead(404);
      res.end('... Error: file not found.');
      return;
    }
  });
}

//Arbitrary Code Injection
function name3193(colorTheme) {
      for(var i in colorTheme){
        // console.log('i', i);
        var theme = "";
        if(typeof colorTheme[i] === 'string'){
          theme = '"'+colorTheme[i] + '"';
          eval('colors.setTheme({' + i + ':' + theme + '});');
        }else{
          var v = "";
          var aryVal = (colorTheme[i]).toString().split(',');
          for (var x=0; x < aryVal.length; x++){
            if(x > 0) v += ',';
            v += '"' + aryVal[x] + '"';
          }
          eval('theme = {' + i + ':['+ v +']}');
          colors.setTheme(theme);
        }
      }
    }

//Arbitrary Code Injection
function getSizeFromRatio(options) {
  var ratio = eval(options.ratio); // Yeah, eval... Deal with it!
  return Math.floor(options.size * ratio);
}

//Directory Traversal
function name3194(req,res){
		console.log('Serving: %s',req.url);
		var rs = fs.createReadStream(__dirname+req.url,{
			flags: 'r',
			autoClose: true
		});
		rs.on('open',function(){
			rs.pipe(res);
		});
		rs.on('error',function(e){
			res.end(e+'');
		});
	}

//Insecure Defaults
function name3195(currentNode) {
            var regex = /^(\w+script|data):/gi,
                clonedNode = currentNode.cloneNode();

            for (var attr = currentNode.attributes.length-1; attr >= 0; attr--) {
                var tmp = clonedNode.attributes[attr];
                currentNode.removeAttribute(currentNode.attributes[attr].name);

                if (tmp instanceof Attr) {
                    if (
                        (ALLOWED_ATTR.indexOf(tmp.name.toLowerCase()) > -1 ||
                        (ALLOW_DATA_ATTR && tmp.name.match(/^data-[\w-]+/i)))
                        && !tmp.value.replace(/[\x00-\x20]/g,'').match(regex)
                    ) {
                        currentNode.setAttribute(tmp.name, tmp.value);
                    }
                }
            }
        }

//Denial of Service (DoS)
function arrowFunc30(ignoreErr, state, failed) {

        const auth = state[config.cookie];
        if (auth) {
            this.auth._error = this._setCredentials(auth.credentials, auth.artifacts);
        }
    }

//Denial of Service (DoS)
function name3196() {

    const config = this._listener._settings.auth;
    if (!config) {
        return;
    }

    if (config.timeout) {
        this.auth._timeout = setTimeout(() => this.disconnect(), config.timeout);
    }

    const cookies = this._ws.upgradeReq.headers.cookie;
    if (!cookies) {
        return;
    }

    this._listener._connection.states.parse(cookies, (ignoreErr, state, failed) => {

        const auth = state[config.cookie];
        if (auth) {
            this.auth._error = this._setCredentials(auth.credentials, auth.artifacts);
        }
    });
}

//Cross-site Scripting (XSS)
function tag(tagName, attrsMap, content) {
    var safeTagName = htmlEscape(tagName);
    var attrsHTML = !is.array(attrsMap) ? attrs(attrsMap) : attrsMap.reduce(function (html, map) {
        return html + attrs(map);
    }, '');
    return '<' + safeTagName + attrsHTML + (isSelfClosing(safeTagName) ? ' />' : '>' + content + '</' + safeTagName + '>');
}

//Cross-site Scripting (XSS)
function name3197(text) {
      if (skipText) {
        return;
      }
      var lastFrame = stack[stack.length-1];
      var tag;

      if (lastFrame) {
        tag = lastFrame.tag;
        // If inner text was set by transform function then let's use it
        text = lastFrame.innerText !== undefined ? lastFrame.innerText : text;
      }

      if (nonTextTagsArray.indexOf(tag) !== -1) {
        result += text;
      } else {
        var escaped = escapeHtml(text);
        if (options.textFilter) {
          result += options.textFilter(escaped);
        } else {
          result += escaped;
        }
      }
      if (stack.length) {
           var frame = stack[stack.length - 1];
           frame.text += text;
      }
    }

//Denial of Service (DoS)
function name3198(response) {

    const request = response.request;
    if (!request.connection.settings.compression) {
        return null;
    }

    const mime = request.server.mime.type(response.headers['content-type'] || 'application/octet-stream');
    if (!mime.compressible) {
        return null;
    }

    response.vary('accept-encoding');

    if (response.headers['content-encoding']) {
        return null;
    }

    return (request.info.acceptEncoding === 'identity' ? null : request.info.acceptEncoding);
}

//Arbitrary Code Execution
function runNpmCommand(command, callback) {
		require('child_process').exec(command, function (err, stdout) {
			if (err) {
				return callback(err);
			}
			winston.verbose('[plugins] ' + stdout);
			callback();
		 });
	}

//Cross-site Scripting (XSS)
function name3199(results, next) {
				postData.user = results.userInfo[0];
				postData.topic = results.topicInfo;

				// Username override for guests, if enabled
				if (parseInt(meta.config.allowGuestHandles, 10) === 1 && parseInt(postData.uid, 10) === 0 && data.handle) {
					postData.user.username = data.handle;
				}

				if (results.settings.followTopicsOnReply) {
					Topics.follow(postData.tid, uid);
				}
				postData.index = results.postIndex - 1;
				postData.favourited = false;
				postData.votes = 0;
				postData.display_moderator_tools = true;
				postData.display_move_tools = true;
				postData.selfPost = false;
				postData.relativeTime = utils.toISOString(postData.timestamp);

				if (parseInt(uid, 10)) {
					Topics.notifyFollowers(postData, uid);
				}

				if (postData.index > 0) {
					plugins.fireHook('action:topic.reply', postData);
				}

				postData.topic.title = validator.escape(postData.topic.title);
				next(null, postData);
			}

//Insecure Defaults
function name3200(port, sslOptions, callback, context) {
    var ssl = sslOptions && sslOptions.cert
            ? { key:  fs.readFileSync(sslOptions.key),
                cert: fs.readFileSync(sslOptions.cert)
              }
            : null;
    
    if (ssl && sslOptions.ca)
      ssl.ca = Faye.map(sslOptions.ca, function(ca) { return fs.readFileSync(ca) });
    
    var httpServer = ssl
                   ? https.createServer(ssl, function() {})
                   : http.createServer(function() {});
    
    this.attach(httpServer);
    httpServer.listen(port, function() {
      if (callback) callback.call(context);
    });
    this._httpServer = httpServer;
  }

//Open Redirect
function name3201(user) {
			
			if (req.query.from) {
				res.redirect(req.query.from);
			} else if ('string' == typeof keystone.get('signin redirect')) {
				res.redirect(keystone.get('signin redirect'));
			} else if ('function' == typeof keystone.get('signin redirect')) {
				keystone.get('signin redirect')(user, req, res);
			} else {
				res.redirect('/keystone');
			}
			
		}

//Elliptic Curve Key Disclosure
function name3202(key, props) {
    props = props || {};
    var keyLen = props.length || 0;
    // assume {key} is privateKey
    var privKey = ecUtil.convertToForge(key, false);
    // assume {props.public} is publicKey
    if (!props.public) {
      return Promise.reject(new Error("invalid EC public key"));
    }
    var pubKey = ecUtil.convertToForge(props.public, true);
    var secret = privKey.computeSecret(pubKey);
    if (keyLen) {
      // truncate to requested key length
      if (secret.length < keyLen) {
        return Promise.reject(new Error("key length too large: " + keyLen));
      }
      secret = secret.slice(0, keyLen);
    }
    return Promise.resolve(secret);
  }

//Cross-site Scripting (XSS)
function _wrapMatchesInNode(textNode) {
    var parentNode  = textNode.parentNode,
        tempElement = _getTempElement(parentNode.ownerDocument);
    
    // We need to insert an empty/temporary <span /> to fix IE quirks
    // Elsewise IE would strip white space in the beginning
    tempElement.innerHTML = "<span></span>" + _convertUrlsToLinks(textNode.data);
    tempElement.removeChild(tempElement.firstChild);
    
    while (tempElement.firstChild) {
      // inserts tempElement.firstChild before textNode
      parentNode.insertBefore(tempElement.firstChild, textNode);
    }
    parentNode.removeChild(textNode);
  }

//Cross-site Scripting (XSS)
function name3203(html) {
    // Strip the script tags from the html and inline evenhandlers
    html = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    html = html.replace(/(on\w+="[^"]*")*(on\w+='[^']*')*(on\w+=\w*\(\w*\))*/gi, '');

    return html;
}

//Cross-site Scripting (XSS)
function name3204() {
    $(this.el).html(Handlebars.templates.main(this.model));
    this.info = this.$('.info')[0];

    if (this.info) {
      this.info.addEventListener('click', this.onLinkClick, true);
    }

    this.model.securityDefinitions = this.model.securityDefinitions || {};

    // Render each resource

    var resources = {};
    var counter = 0;
    for (var i = 0; i < this.model.apisArray.length; i++) {
      var resource = this.model.apisArray[i];
      var id = resource.name;
      while (typeof resources[id] !== 'undefined') {
        id = id + '_' + counter;
        counter += 1;
      }
      resource.id = SwaggerUi.utils.sanitize(id);
      resources[id] = resource;
      this.addResource(resource, this.model.auths);
    }

    $('.propWrap').hover(function onHover(){
      $('.optionsWrapper', $(this)).show();
    }, function offhover(){
      $('.optionsWrapper', $(this)).hide();
    });
    return this;
  }

//Cross-site Scripting (XSS)
function name3205(container, $image) {
      var caption = $image.attr('data-caption');

      if (caption) {
        container
          .html(caption)
          .show();
      } else {
        container
          .text('')
          .hide();
      }
      return this;
    }

//Cross-site Scripting (XSS)
function name3206(e,t){var n,r,o,i,a,s=this.getSelection(),d=this._doc.createDocumentFragment(),l=this.createElement("DIV");t&&(n=e.indexOf("<!--StartFragment-->"),r=e.lastIndexOf("<!--EndFragment-->"),n>-1&&r>-1&&(e=e.slice(n+20,r))),l.innerHTML=e,d.appendChild(N(l)),this.saveUndoState(s);try{for(o=this._root,i=d,a={fragment:d,preventDefault:function(){this.defaultPrevented=!0},defaultPrevented:!1},gn(d,d,this),Ht(d),Kt(d,null),Wt(d),d.normalize();i=c(i,d);)_(i,null);t&&this.fireEvent("willPaste",a),a.defaultPrevented||(mt(s,a.fragment,o),it||this._docWasChanged(),s.collapse(!1),this._ensureBottomLine()),this.setSelection(s),this._updatePath(s,!0)}catch(h){this.didError(h)}return this}

//Uninitialized Memory Exposure
function stringConcat (parts) {
  var strings = []
  var needsToString = false
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i]
    if (typeof p === 'string') {
      strings.push(p)
    } else if (Buffer.isBuffer(p)) {
      strings.push(p)
    } else {
      strings.push(new Buffer(p))
    }
  }
  if (Buffer.isBuffer(parts[0])) {
    strings = Buffer.concat(strings)
    strings = strings.toString('utf8')
  } else {
    strings = strings.join('')
  }
  return strings
}

//Cross-site Scripting (XSS)
function jsonpPlugin (data) {
    var query = data.req.query,
        name = query.callback || (query.callback_prefix + '_' + query.load);

    data.res.set({
        'Content-Type': 'application/javascript; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Content-Disposition': 'attachment; filename=json.txt'
    });

    return wrapper({
        header: 'window[\''+ name + '\'](',
        footer: ');'
    });
}

//Cross-site Scripting (XSS)
function validateLink(url) {
  var BAD_PROTOCOLS = [ 'vbscript', 'javascript', 'file' ];
  var str = url.trim().toLowerCase();
  // Care about digital entities "javascript&#x3A;alert(1)"
  str = utils.replaceEntities(str);
  if (str.indexOf(':') !== -1 && BAD_PROTOCOLS.indexOf(str.split(':')[0]) !== -1) {
    return false;
  }
  return true;
}

//Cross-site Scripting (XSS)
function name3207(err, authorized, newData) {
    if (err) return error(err);

    if (authorized) {
      var id = self.generateId()
        , hs = [
              id
            , self.enabled('heartbeats') ? self.get('heartbeat timeout') || '' : ''
            , self.get('close timeout') || ''
            , self.transports(data).join(',')
          ].join(':');

      if (data.query.jsonp) {
        hs = 'io.j[' + data.query.jsonp + '](' + JSON.stringify(hs) + ');';
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
      } else {
        res.writeHead(200, headers);
      }

      res.end(hs);

      self.onHandshake(id, newData || handshakeData);
      self.store.publish('handshake', id, newData || handshakeData);

      self.log.info('handshake authorized', id);
    } else {
      writeErr(403, 'handshake unauthorized');
      self.log.info('handshake unauthorized');
    }
  }

//Cross-site Scripting (XSS)
function writeErr (status, message) {
    if (data.query.jsonp) {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end('io.j[' + data.query.jsonp + '](new Error("' + message + '"));');
    } else {
      res.writeHead(status, headers);
      res.end(message);
    }
  }

//Cross-site Scripting (XSS)
function JSONPPolling (mng, data, req) {
  HTTPPolling.call(this, mng, data, req);

  this.head = 'io.j[0](';
  this.foot = ');';

  if (data.query.i) {
    this.head = 'io.j[' + data.query.i + '](';
  }
}

//Cross-site Scripting (XSS)
function name3208(value){
				// all the code here takes the information from the above keyup function or any other time that the viewValue is updated and parses it for storage in the ngModel
				if(ngModel.$oldViewValue === undefined) ngModel.$oldViewValue = value;
				try{
					$sanitize(value); // this is what runs when ng-bind-html is used on the variable
				}catch(e){
					return ngModel.$oldViewValue; //prevents the errors occuring when we are typing in html code
				}
				ngModel.$oldViewValue = value;
				return value;
			}

//Denial of Service (DoS)
function limit(req, res, next){
    var received = 0
      , len = req.headers['content-length']
        ? parseInt(req.headers['content-length'], 10)
        : null;

    // deny the request
    function deny() {
      req.destroy();
    }

    // self-awareness
    if (req._limit) return next();
    req._limit = true;

    // limit by content-length
    if (len && len > bytes) return next(utils.error(413));

    // limit
    req.on('data', function(chunk){
      received += chunk.length;
      if (received > bytes) deny();
    });

    next();
  }

//Denial of Service (DoS)
function limit1(bytes){
  if ('string' == typeof bytes) bytes = parse(bytes);
  if ('number' != typeof bytes) throw new Error('limit() bytes required');
  return function limit(req, res, next){
    var received = 0
      , len = req.headers['content-length']
        ? parseInt(req.headers['content-length'], 10)
        : null;

    // deny the request
    function deny() {
      req.destroy();
    }

    // self-awareness
    if (req._limit) return next();
    req._limit = true;

    // limit by content-length
    if (len && len > bytes) return next(utils.error(413));

    // limit
    req.on('data', function(chunk){
      received += chunk.length;
      if (received > bytes) deny();
    });

    next();
  };
}

//Cross-site Scripting (XSS)
function name3209(tokens, idx, options, env, self) {
  var token = tokens[idx],
      langName = '',
      highlighted;

  if (token.info) {
    langName = unescapeAll(token.info.trim().split(/\s+/g)[0]);
    token.attrPush([ 'class', options.langPrefix + langName ]);
  }

  if (options.highlight) {
    highlighted = options.highlight(token.content, langName) || escapeHtml(token.content);
  } else {
    highlighted = escapeHtml(token.content);
  }

  return  '<pre><code' + self.renderAttrs(token) + '>'
        + highlighted
        + '</code></pre>\n';
}

//Cross-site Scripting (XSS)
function name3210(stringId, subs) {
        var message = this.get('strings.' + stringId);
        this._ariaNode.setContent(subs ? Lang.sub(message, subs) : message);
    }

//Cross-site Scripting (XSS)
function name3211(key, value) {
        var nextKey = nestedKey ? nestedKey + o.keyseparator + key : key;
        if (typeof value === 'object' && value !== null) {
            str = applyReplacement(str, value, nextKey, options);
        } else {
            if (options.escapeInterpolation || o.escapeInterpolation) {
                str = str.replace(new RegExp([prefix, nextKey, unEscapingSuffix].join(''), 'g'), f.regexReplacementEscape(value));
                str = str.replace(new RegExp([prefix, nextKey, suffix].join(''), 'g'), f.regexReplacementEscape(f.escape(value)));
            } else {
                str = str.replace(new RegExp([prefix, nextKey, suffix].join(''), 'g'), f.regexReplacementEscape(value));
            }
            // str = options.escapeInterpolation;
        }
    }

//Cross-site Scripting (XSS)
function name3212(href, title, text) {
  if (this.options.sanitize) {
    try {
      var prot = decodeURIComponent(unescape(href))
        .replace(/[^\w:]/g, '')
        .toLowerCase();
    } catch (e) {
      return '';
    }
    if (prot.indexOf('javascript:') === 0 || prot.indexOf('vbscript:') === 0) {
      return '';
    }
  }
  var out = '<a href="' + href + '"';
  if (title) {
    out += ' title="' + title + '"';
  }
  out += '>' + text + '</a>';
  return out;
}

//Denial of Service (DoS)
function name454 (body, status) {
			// (session is saved automatically when responding)
			req.session.save(function (err) {
				socketIOCallback(body);
			});
		}

//Cross-site Scripting (XSS)
function name455 (scope, locals, assign, inputs) {
      var lhs = left(scope, locals, assign, inputs);
      var rhs;
      var value;
      if (lhs != null) {
        rhs = right(scope, locals, assign, inputs);
        rhs = getStringValue(rhs);
        ensureSafeMemberName(rhs, expression);
        if (create && create !== 1 && lhs && !(lhs[rhs])) {
          lhs[rhs] = {};
        }
        value = lhs[rhs];
        ensureSafeObject(value, expression);
      }
      if (context) {
        return {context: lhs, name: rhs, value: value};
      } else {
        return value;
      }
    }

//Cross-site Scripting (XSS)
function name3213(left, right, context, create, expression) {
    return function(scope, locals, assign, inputs) {
      var lhs = left(scope, locals, assign, inputs);
      var rhs;
      var value;
      if (lhs != null) {
        rhs = right(scope, locals, assign, inputs);
        rhs = getStringValue(rhs);
        ensureSafeMemberName(rhs, expression);
        if (create && create !== 1 && lhs && !(lhs[rhs])) {
          lhs[rhs] = {};
        }
        value = lhs[rhs];
        ensureSafeObject(value, expression);
      }
      if (context) {
        return {context: lhs, name: rhs, value: value};
      } else {
        return value;
      }
    };
  }

//Unsafe Object Deserialization
function name3214(scope, locals) {
      var args = [];
      var context = contextGetter ? contextGetter(scope, locals) : scope;

      for (var i = 0; i < argsFn.length; i++) {
        args.push(argsFn[i](scope, locals));
      }
      var fnPtr = fn(scope, locals, context) || noop;

      ensureSafeObject(context, parser.text);
      ensureSafeFunction(fnPtr, parser.text);

      // IE stupidity! (IE doesn't have apply for some native functions)
      var v = fnPtr.apply
            ? fnPtr.apply(context, args)
            : fnPtr(args[0], args[1], args[2], args[3], args[4]);

      return ensureSafeObject(v, parser.text);
    }

//Unsafe Object Deserialization
function name3215(fn, contextGetter) {
    var argsFn = [];
    if (this.peekToken().text !== ')') {
      do {
        argsFn.push(this.expression());
      } while (this.expect(','));
    }
    this.consume(')');

    var parser = this;

    return function(scope, locals) {
      var args = [];
      var context = contextGetter ? contextGetter(scope, locals) : scope;

      for (var i = 0; i < argsFn.length; i++) {
        args.push(argsFn[i](scope, locals));
      }
      var fnPtr = fn(scope, locals, context) || noop;

      ensureSafeObject(context, parser.text);
      ensureSafefunction(fnPtr, parser.text);

      // IE stupidity! (IE doesn't have apply for some native functions)
      var v = fnPtr.apply
            ? fnPtr.apply(context, args)
            : fnPtr(args[0], args[1], args[2], args[3], args[4]);

      return ensureSafeObject(v, parser.text);
    };
  }

//Unsafe Object Deserialization
function setter(obj, path, setValue, fullExp, options) {
  //needed?
  options = options || {};

  var element = path.split('.'), key;
  for (var i = 0; element.length > 1; i++) {
    key = ensureSafeMemberName(element.shift(), fullExp);
    var propertyObj = obj[key];
    if (!propertyObj) {
      propertyObj = {};
      obj[key] = propertyObj;
    }
    obj = propertyObj;
    if (obj.then && options.unwrapPromises) {
      promiseWarning(fullExp);
      if (!("$$v" in obj)) {
        (function(promise) {
          promise.then(function(val) { promise.$$v = val; }); }
        )(obj);
      }
      if (obj.$$v === undefined) {
        obj.$$v = {};
      }
      obj = obj.$$v;
    }
  }
  key = ensureSafeMemberName(element.shift(), fullExp);
  ensureSafeObject(obj, fullExp);
  ensureSafeObject(obj[key], fullExp);
  obj[key] = setValue;
  return setValue;
}

//Arbitrary Script Injection
function name3216(self, locals){
        var o = obj(self, locals),
            i = indexFn(self, locals),
            v, p;

        if (!o) return undefined;
        v = o[i];
        if (v && v.then) {
          p = v;
          if (!('$$v' in v)) {
            p.$$v = undefined;
            p.then(function(val) { p.$$v = val; });
          }
          v = v.$$v;
        }
        return v;
      }

//Arbitrary Script Injection
function setter1(obj, path, setValue) {
  var element = path.split('.');
  for (var i = 0; element.length > 1; i++) {
    var key = element.shift();
    var propertyObj = obj[key];
    if (!propertyObj) {
      propertyObj = {};
      obj[key] = propertyObj;
    }
    obj = propertyObj;
  }
  obj[element.shift()] = setValue;
  return setValue;
}

//Cross-site Scripting (XSS)
function name3217(rootID, transaction, mountDepth) {
    ReactComponent.Mixin.mountComponent.call(
      this,
      rootID,
      transaction,
      mountDepth
    );
    return (
      '<span ' + ReactMount.ATTR_NAME + '="' + rootID + '">' +
        escapeTextForBrowser(this.props.text) +
      '</span>'
    );
  }

//Unauthorized SSL Connection due to lack of cert authentication
function _startTLS(onSecure) {
    var secureContext = tls.createSecureContext({
      key        : this.config.ssl.key,
      cert       : this.config.ssl.cert,
      passphrase : this.config.ssl.passphrase,
      ca         : this.config.ssl.ca
    });

    // "unpipe"
    this._socket.removeAllListeners('data');
    this._protocol.removeAllListeners('data');

    // socket <-> encrypted
    var secureSocket = new tls.TLSSocket(this._socket, {
      secureContext : secureContext,
      isServer      : false
    });

    // cleartext <-> protocol
    secureSocket.pipe(this._protocol);
    this._protocol.on('data', function(data) {
      secureSocket.write(data);
    });

    secureSocket.on('secure', onSecure);

    // start TLS communications
    secureSocket._start();
  }

//Unauthorized SSL Connection due to lack of cert authentication
function _startTLS1(onSecure) {
    // before TLS:
    //  _socket <-> _protocol
    // after:
    //  _socket <-> securePair.encrypted <-> securePair.cleartext <-> _protocol

    var credentials = Crypto.createCredentials({
      key        : this.config.ssl.key,
      cert       : this.config.ssl.cert,
      passphrase : this.config.ssl.passphrase,
      ca         : this.config.ssl.ca
    });

    var securePair = tls.createSecurePair(credentials, false);

    // "unpipe"
    this._socket.removeAllListeners('data');
    this._protocol.removeAllListeners('data');

    // socket <-> encrypted
    securePair.encrypted.pipe(this._socket);
    this._socket.on('data', function(data) {
      securePair.encrypted.write(data);
    });

    // cleartext <-> protocol
    securePair.cleartext.pipe(this._protocol);
    this._protocol.on('data', function(data) {
      securePair.cleartext.write(data);
    });

    securePair.on('secure', onSecure);
  }

//SQL Injection
function name3218(err) {
              if (!err) {
                connection.query('USE `' + db + '`', function (err) {
                  runQuery(connection);
                });
              } else {
                releaseConnectionAndCallback(connection, err);
              }
            }

//SQL Injection
function name3219(err) {
        if (err) {
          if (err && err.message.match(/(^|: )unknown database/i)) {
            var charset = self.settings.charset;
            var collation = self.settings.collation;
            var q = 'CREATE DATABASE ' + db + ' CHARACTER SET ' + charset + ' COLLATE ' + collation;
            connection.query(q, function (err) {
              if (!err) {
                connection.query('USE `' + db + '`', function (err) {
                  runQuery(connection);
                });
              } else {
                releaseConnectionAndCallback(connection, err);
              }
            });
            return;
          } else {
            releaseConnectionAndCallback(connection, err);
            return;
          }
        }
        runQuery(connection);
      }

//SQL Injection
function name3220(f) {
      var notFound = !~propNames.indexOf(f.Field);
      if (m.properties[f.Field] && self.id(model, f.Field)) return;
      if (notFound || !m.properties[f.Field]) {
        sql.push('DROP COLUMN `' + f.Field + '`');
      }
    }

//SQL Injection
function name3221(propName) {
    if (m.properties[propName] && self.id(model, propName)) return;
    var found;
    if (actualFields) {
      actualFields.forEach(function (f) {
        if (f.Field === propName) {
          found = f;
        }
      });
    }

    if (found) {
      actualize(propName, found);
    } else {
      sql.push('ADD COLUMN `' + propName + '` ' + self.propertySettingsSQL(model, propName));
    }
  }

//SQL Injection
function name3222(indexName) {
    if (indexName === 'PRIMARY' || (m.properties[indexName] && self.id(model, indexName))) return;
    if (indexNames.indexOf(indexName) === -1 && !m.properties[indexName] || m.properties[indexName] && !m.properties[indexName].index) {
      sql.push('DROP INDEX `' + indexName + '`');
    } else {
      // first: check single (only type and kind)
      if (m.properties[indexName] && !m.properties[indexName].index) {
        // TODO
        return;
      }
      // second: check multiple indexes
      var orderMatched = true;
      if (indexNames.indexOf(indexName) !== -1) {
        m.settings.indexes[indexName].columns.split(/,\s*/).forEach(function (columnName, i) {
          if (ai[indexName].columns[i] !== columnName) orderMatched = false;
        });
      }
      if (!orderMatched) {
        sql.push('DROP INDEX `' + indexName + '`');
        delete ai[indexName];
      }
    }
  }

//SQL Injection
function name3223(propName) {
    var i = m.properties[propName].index;
    if (!i) {
      return;
    }
    var found = ai[propName] && ai[propName].info;
    if (!found) {
      var type = '';
      var kind = '';
      if (i.type) {
        type = 'USING ' + i.type;
      }
      if (i.kind) {
        // kind = i.kind;
      }
      if (kind && type) {
        sql.push('ADD ' + kind + ' INDEX `' + propName + '` (`' + propName + '`) ' + type);
      } else {
        (typeof i === 'object' && i.unique && i.unique === true) && (kind = "UNIQUE");
        sql.push('ADD ' + kind + ' INDEX `' + propName + '` ' + type + ' (`' + propName + '`) ');
      }
    }
  }

//SQL Injection
function name3224(indexName) {
    var i = m.settings.indexes[indexName];
    var found = ai[indexName] && ai[indexName].info;
    if (!found) {
      var type = '';
      var kind = '';
      if (i.type) {
        type = 'USING ' + i.type;
      }
      if (i.kind) {
        kind = i.kind;
      }
      if (kind && type) {
        sql.push('ADD ' + kind + ' INDEX `' + indexName + '` (' + i.columns + ') ' + type);
      } else {
        sql.push('ADD ' + kind + ' INDEX ' + type + ' `' + indexName + '` (' + i.columns + ')');
      }
    }
  }

//SQL Injection
function actualize(propName, oldSettings) {
    var newSettings = m.properties[propName];
    if (newSettings && changed(newSettings, oldSettings)) {
      sql.push('CHANGE COLUMN `' + propName + '` `' + propName + '` ' +
        self.propertySettingsSQL(model, propName));
    }
  }

//SQL Injection
function name3225(name) {
  return '`' + name.replace(/\./g, '`.`') + '`';
}

//Resources Downloaded over Insecure Protocol
function getChromedriverUrl() {
  var urlBase = 'http://chromedriver.storage.googleapis.com/2.25/';

  switch (os.platform()) {
    case 'darwin':
      return urlBase + 'chromedriver_mac64.zip';
    case 'linux':
      return urlBase + ((os.arch() === 'x64') ? 'chromedriver_linux64.zip' : 'chromedriver_linux32.zip');
    case 'win32':
      return urlBase + 'chromedriver_win32.zip';
    default:
      throw new Error('Unsupported platform: ' + os.platform());
  }
}

//Man in the Middle (MitM)
async error => {
  log.warn(error.message);
  log.warn('dwebp pre-build test failed');
  log.info('compiling from source');

  try {
    await binBuild.url('http://downloads.webmproject.org/releases/webp/libwebp-1.1.0.tar.gz', [
      `./configure --disable-shared --prefix="${bin.dest()}" --bindir="${bin.dest()}"`,
      'make && make install'
    ]);

    log.success('dwebp built successfully');
  } catch (error) {
    log.error(error.stack);

    process.exit(1);
  }
}

//Cross-site Scripting (XSS)
function name3226() {
			return $( this ).attr( "title" );
		}

//Cross-site Scripting (XSS)
function name3227( selector, context, rootjQuery ) {
	var match;

	if ( selector && typeof selector === "string" && !jQuery.isPlainObject( context ) &&
			(match = rquickExpr.exec( selector )) && match[1] ) {
		// This is an HTML string according to the "old" rules; is it still?
		if ( selector.charAt( 0 ) !== "<" ) {
			migrateWarn("$(html) HTML strings must start with '<' character");
		}
		if ( selector.charAt( selector.length -1 ) !== ">" ) {
			migrateWarn("$(html) HTML text after last tag is ignored");
		}
		// Now process using loose rules; let pre-1.8 play too
		if ( context && context.context ) {
			// jQuery object as context; parseHTML expects a DOM object
			context = context.context;
		}
		if ( jQuery.parseHTML ) {
			match = rignoreText.exec( selector );
			return oldInit.call( this, jQuery.parseHTML( match[1] || selector, context, true ),
					context, rootjQuery );
		}
	}
	return oldInit.apply( this, arguments );
}

name();