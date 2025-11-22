import Document, { Html, Head, Main, NextScript } from 'next/document'

export default class MyDocument extends Document {
render() {
return (
<Html>
<Head>
<link rel="icon" href="/favicon.ico" />
{/* optionally: <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" /> */}
</Head>
<body>
<Main />
<NextScript />
</body>
</Html>
)
}
}