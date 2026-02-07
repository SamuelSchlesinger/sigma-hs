module Crypto.DuplexSponge where

import Data.ByteString (ByteString)

class DuplexSponge s where
    type Unit s
    newDuplexSponge :: ByteString -> s
    absorbDuplexSponge :: s -> Unit s -> s
    squeezeDuplexSponge :: s -> Int -> ([Unit s], s)
