{-# OPTIONS --safe --without-K #-}
module PackageAuthority where

open import Agda.Builtin.Equality using (_≡_; refl)

data Scope : Set where
  user system driver firmware : Scope

data Authority : Set where
  arach-native arach-hardware : Authority

data Admitted : Scope → Authority → Set where
  native-user : Admitted user arach-native
  native-system : Admitted system arach-native
  hardware-driver : Admitted driver arach-hardware
  hardware-firmware : Admitted firmware arach-hardware

data ⊥ : Set where

driver-cannot-use-native : Admitted driver arach-native → ⊥
driver-cannot-use-native ()

firmware-cannot-use-native : Admitted firmware arach-native → ⊥
firmware-cannot-use-native ()

system-is-native : (proof : Admitted system arach-native) →
                   proof ≡ native-system
system-is-native native-system = refl

driver-is-hardware : (proof : Admitted driver arach-hardware) →
                     proof ≡ hardware-driver
driver-is-hardware hardware-driver = refl

