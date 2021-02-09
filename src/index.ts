export function parse(rawLines: string|Array<string>): any {
	let lines
	if (typeof rawLines === 'string') {
		lines = rawLines.split('\n')
	} else if (typeof rawLines==='object' && Array.isArray(rawLines)) {
		lines = rawLines
	} else {
		throw new Error('mysql-parse-grants.parse: Parameter does not match specification')
	}

	return null
}
