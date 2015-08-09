package org.whispersystems

object Main {
  
  case class User(name: String) {

    val channel = Axolotl(name)
    var mbx = List[String]()

    def meet(other: User): Unit = {
      channel.init(other.channel.introduce(), verify = false)
    }

    def replay() {
      mbx.foreach(m => println(s"$name # " + m))
      mbx = List[String]()
    }
    
    def send(encryptedLine: Array[Byte]) {
      mbx = mbx :+ new String(channel.decryptMessage(encryptedLine), "UTF-8")
    }
    
    def encrypt(line: String): Array[Byte] =
      channel.encryptMessage(line.getBytes("UTF-8"))
  }

  val alice = User("Alice")
  val bob   = User("Bob")
  
  def main(args: Array[String]) {
    println("Hello World!")

    alice .meet(bob)
    bob   .meet(alice)

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
    bob.send(alice.encrypt(line))
  }

  def sendAliceSecure(line: String) {
    alice.send(bob.encrypt(line))
  }

  def replayBob() {
//    bob.mbx.forEach(function (m) {
//      console.log("# Alice: ", m);
//    })
//
//    bob.mbx = null;
    bob.replay()
  }

  def replayAlice() {
    alice.replay()
  }
}
