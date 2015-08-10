import org.whispersystems.Axolotl

import scala.collection.immutable.HashMap

object Main {

  case class User(name: String) {

    val proto = Axolotl()

    var channels  = new HashMap[User, proto.SecureChannel]
    var mailbox   = new HashMap[User, List[String]]

    private def establishChannelWith(otherParty: User): proto.SecureChannel = {
      val c = proto.open()
      channels = channels + (otherParty -> c)
      c
    }

    def meet(otherParty: User) {
      val own   = establishChannelWith(otherParty)
      val other = otherParty.establishChannelWith(this)

      own.handshake(other.introduce(), authenticate = false)
    }

    def replay() {
      mailbox.foreach {
        case (u, ms) => ms.foreach(m => println(s"${u.name}# ${m}"))
      }
      mailbox = new HashMap[User, List[String]]
    }

    def sendFrom(otherParty: User, encryptedLine: Array[Byte]) {
      mailbox = mailbox +
        (otherParty ->
          (mailbox.getOrElse(otherParty, List()) :+ new String(channels(otherParty).decryptMessage(encryptedLine), "UTF-8")))
    }
    
    def encryptFor(otherParty: User, line: String): Array[Byte] =
      channels(otherParty).encryptMessage(line.getBytes("UTF-8"))
  }

  val alice = User("Alice")
  val bob   = User("Bob")
  
  def main(args: Array[String]) {
    println("Hello World!")

    alice.meet(bob)

    // # Alice
    sendBobSecure("Ola, Bob!")
    sendBobSecure("How're you?")
    sendBobSecure("What's up?")
    replayBob()

    // # Bob
    sendAliceSecure("I'm fine!")
    sendAliceSecure("And you?")
    replayAlice()

    // # Alice
    sendBobSecure("Cool!")
    sendBobSecure("I'm fine too, Bob")
    replayBob()
  }

  def sendBobSecure(line: String) {
    bob.sendFrom(alice, alice.encryptFor(bob, line))
  }

  def sendAliceSecure(line: String) {
    alice.sendFrom(bob, bob.encryptFor(alice, line))
  }

  def replayBob() {
    bob.replay()
  }

  def replayAlice() {
    alice.replay()
  }
}
