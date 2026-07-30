program build_rank_test
  use, intrinsic :: iso_c_binding, only: c_bool, c_double, c_int
  use arach_build_rank_module, only: arach_build_rank
  implicit none
  real(c_double) :: untrusted
  real(c_double) :: leaf
  real(c_double) :: critical

  untrusted = arach_build_rank(1.0_c_double, 20_c_int, .true._c_bool, &
                               1.0_c_double, .false._c_bool)
  leaf = arach_build_rank(0.2_c_double, 0_c_int, .false._c_bool, &
                          2.0_c_double, .true._c_bool)
  critical = arach_build_rank(1.0_c_double, 5_c_int, .true._c_bool, &
                              2.0_c_double, .true._c_bool)

  if (abs(untrusted + 1.0_c_double) > epsilon(untrusted)) error stop 1
  if (critical <= leaf) error stop 2
end program build_rank_test
