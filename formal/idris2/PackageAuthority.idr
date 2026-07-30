module PackageAuthority

%default total

public export
data Scope = User | System | Driver | Firmware

public export
data Authority = ArachNative | ArachHardware

public export
data Source
  = LockedGit String
  | LockedArchive String
  | LockedCrate String
  | LockedLocal String

public export
data Admitted : Scope -> Authority -> Type where
  NativeUser : Admitted User ArachNative
  NativeSystem : Admitted System ArachNative
  HardwareDriver : Admitted Driver ArachHardware
  HardwareFirmware : Admitted Firmware ArachHardware

public export
admit : (scope : Scope) -> (authority : Authority) ->
        Maybe (Admitted scope authority)
admit User ArachNative = Just NativeUser
admit User ArachHardware = Nothing
admit System ArachNative = Just NativeSystem
admit System ArachHardware = Nothing
admit Driver ArachNative = Nothing
admit Driver ArachHardware = Just HardwareDriver
admit Firmware ArachNative = Nothing
admit Firmware ArachHardware = Just HardwareFirmware

public export
Uninhabited (Admitted Driver ArachNative) where
  uninhabited NativeUser impossible
  uninhabited NativeSystem impossible
  uninhabited HardwareDriver impossible
  uninhabited HardwareFirmware impossible

public export
Uninhabited (Admitted Firmware ArachNative) where
  uninhabited NativeUser impossible
  uninhabited NativeSystem impossible
  uninhabited HardwareDriver impossible
  uninhabited HardwareFirmware impossible

public export
driverCannotUseNative : Admitted Driver ArachNative -> Void
driverCannotUseNative value = absurd value

public export
firmwareCannotUseNative : Admitted Firmware ArachNative -> Void
firmwareCannotUseNative value = absurd value

public export
record Candidate where
  constructor MkCandidate
  source : Source
  criticality : Nat
  dependents : Nat

public export
prefer : Candidate -> Candidate -> Candidate
prefer left right =
  if right.criticality + right.dependents >
     left.criticality + left.dependents
    then right
    else left

public export
selectBuild : List Candidate -> Maybe Candidate
selectBuild [] = Nothing
selectBuild (candidate :: rest) = Just (foldl prefer candidate rest)
