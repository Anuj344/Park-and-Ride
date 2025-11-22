import Link from 'next/link'
import styles from '../styles/Home.module.css'

export default function Home() {
  return (
    <div className={styles.container}>
      {/* Hero Section */}
      <header className={styles.hero}>
        <h1 className={styles.title}>Park & Ride</h1>
        <p className={styles.subtitle}>
          A smart parking solution that lets you reserve your spot in advance, 
          avoid long waits, and enjoy a stress-free travel experience.
        </p>

        <div className={styles.actions}>
          <Link href="/login">
            <button className={`${styles.button} ${styles.loginBtn}`}>
              Login
            </button>
          </Link>
          <Link href="/register">
            <button className={`${styles.button} ${styles.signupBtn}`}>
              Sign Up
            </button>
          </Link>
          <Link href="/dashboard">
            <button className={`${styles.button} ${styles.dashboardBtn}`}>
              Dashboard
            </button>
          </Link>
        </div>
      </header>

      {/* Features Section */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Why choose Park & Ride?</h2>
        <ul className={styles.list}>
          <li>Reserve parking spots online anytime</li>
          <li>Save time and avoid last-minute stress</li>
          <li>Secure and reliable parking system</li>
          <li>Easy cancellations and real-time updates</li>
        </ul>
      </section>

      {/* Booking Policies */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Booking Policies</h2>
        <ul className={styles.list}>
          <li>Refund available if cancellation is made at least 2 hours before the booking time.</li>
          <li>No refund for cancellations made less than 2 hours before booking.</li>
          <li>Every booking comes with a unique QR code for secure check-in and validation.</li>
          <li>Our pricing uses a smart cost model powered by a sigmoid function, ensuring fair and dynamic pricing based on demand.</li>
        </ul>
      </section>

      {/* How It Works */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>How it works</h2>
        <ol className={styles.steps}>
          <li>Sign up and create your account.</li>
          <li>Choose your parking location and reserve a slot.</li>
          <li>Get your unique QR code for entry.</li>
          <li>Park with ease and travel stress-free.</li>
        </ol>
      </section>
    </div>
  )
}
