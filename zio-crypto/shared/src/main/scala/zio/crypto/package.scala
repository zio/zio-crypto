package zio

package object crypto {

  def unsecure[A](f: Secure[Any] => A): A = f(new Secure[Any] {})
}
