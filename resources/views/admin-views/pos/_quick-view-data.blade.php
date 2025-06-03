<div class="modal fade" id="free-product-modal" tabindex="-1" role="dialog" aria-labelledby="freeProductModalLabel"
    aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="freeProductModalLabel">Free Product</h5>
            </div>
            <div class="modal-body">
                <div class="row">
                   
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="dismiss" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>
<div class="modal-header p-2">
    <h4 class="modal-title product-title"></h4>
    <button class="close call-when-done" type="button" data-dismiss="modal" aria-label="Close">
        <span aria-hidden="true">&times;</span>
    </button>
</div>
<div class="modal-body">
    <div class="d-flex flex-wrap gap-3">
        <div class="d-flex align-items-center justify-content-center active">
            <img class="img-responsive rounded" width="160"
                 src="{{$product['imageFullPath']}}"
                 data-zoom="{{$product['imageFullPath']}}"
                 alt="{{ translate('product') }}">
            <div class="cz-image-zoom-pane"></div>
        </div>

        <?php
$pb = json_decode($product->branch_products, true);
$discountData = [];
if (isset($pb[0])) {
    $price = $pb[0]['price'];
    $discountData = [
        'discount_type' => $pb[0]['discount_type'],
        'discount' => $pb[0]['discount']
    ];
} else {
    $price = $product['price'];
    $discountType = $product['discount_type'];
    $discount = $product['discount'];
    $discountData = [
        'discount_type' => $product['discount_type'],
        'discount' => $product['discount']
    ];
}
        ?>
        <div class="details">
            <div class="break-all">
                <a href="#" class="d-block h3 mb-2 product-title">{{ Str::limit($product->name, 100) }}</a>
            </div>

            <div class="mb-2 text-dark d-flex align-items-baseline gap-2">
                <h3 class="font-weight-normal text-accent mb-0">
                    {{Helpers::set_symbol(($price - Helpers::discount_calculate($discountData, $price))) }}
                </h3>
                @if($discountData['discount'] > 0)
                    <strike class="fz-12">
                        {{Helpers::set_symbol($price) }}
                    </strike>
                @endif
            </div>

            @if($discountData['discount'] > 0)
                <div class="mb-3 text-dark">
                    <strong>{{translate('Discount : ')}}</strong>
                    <strong
                        id="set-discount-amount">{{Helpers::set_symbol(\App\CentralLogics\Helpers::discount_calculate($discountData, $price)) }}</strong>
                </div>
            @endif
        </div>
    </div>
    <div class="row pt-2">
        <div class="col-12">
            <?php
$cart = false;
if (session()->has('cart')) {
    foreach (session()->get('cart') as $key => $cartItem) {
        if (is_array($cartItem) && $cartItem['id'] == $product['id']) {
            $cart = $cartItem;
        }
    }
}

            ?>
            <h3 class="mt-3">{{translate('description')}}</h3>
            <div class="d-block text-break text-dark __descripiton-txt __not-first-hidden">
                <div>
                    <p>
                        {!! $product->description !!}
                    </p>
                </div>
                <div class="show-more text-info text-center">
                    <span class="">See More</span>
                </div>
            </div>
            <form id="add-to-cart-form" class="mb-2">
                @csrf
                <input type="hidden" name="id" value="{{ $product->id }}">
                <input type="hidden" name="category_id" value="{{ $product->category_ids }}">
                @if (isset($product->branch_products) && count($product->branch_products))
                    @foreach($product->branch_products as $branch_product)
                        @foreach ($branch_product->variations as $key => $choice)
                            @if (isset($choice->price) == false)
                                <div class="h3 p-0 pt-2">
                                    {{ $choice['name'] }}
                                    <small class="text-muted custom-text-size12">
                                        ({{ ($choice['required'] == 'on') ? translate('Required') : translate('optional') }})
                                    </small>
                                </div>
                                @if ($choice['min'] != 0 && $choice['max'] != 0)
                                    <small class="d-block mb-3">
                                        {{ translate('You_need_to_select_minimum_ ') }} {{ $choice['min'] }} {{ translate('to_maximum_ ') }} {{ $choice['max'] }} {{ translate('options') }}
                                    </small>
                                @endif

                                <div>
                                    <input type="hidden"  name="variations[{{ $key }}][min]" value="{{ $choice['min'] }}" >
                                    <input type="hidden"  name="variations[{{ $key }}][max]" value="{{ $choice['max'] }}" >
                                    <input type="hidden"  name="variations[{{ $key }}][required]" value="{{ $choice['required'] }}" >
                                    <input type="hidden" name="variations[{{ $key }}][name]" value="{{ $choice['name'] }}">
                                    @foreach ($choice['values'] as $k => $option)
                                        <div class="form-check form--check d-flex pr-5 mr-6">
                                            <input class="form-check-input" type="{{ ($choice['type'] == "multi") ? "checkbox" : "radio"}}" id="choice-option-{{ $key }}-{{ $k }}"
                                                   name="variations[{{ $key }}][values][label][]" value="{{ $option['label'] }}" autocomplete="off">

                                            <label class="form-check-label"
                                                   for="choice-option-{{ $key }}-{{ $k }}">{{ Str::limit($option['label'], 20, '...') }}</label>
                                            <span class="ml-auto">{{Helpers::set_symbol($option['optionPrice']) }}</span>
                                        </div>
                                    @endforeach
                                </div>

                            @endif
                        @endforeach
                    @endforeach

                @endif

                <div class="d-flex align-items-center justify-content-between mb-3 mt-4">
                    <h3 class="product-description-label mt-2 mb-0">{{translate('Quantity')}}:</h3>

                    <div class="product-quantity d-flex align-items-center">
                        <div class="product-quantity-group d-flex align-items-center">
                            <button class="btn btn-number text-dark p-2" type="button"
                                    data-type="minus" data-field="quantity"
                                    disabled="disabled">
                                    <i class="tio-remove font-weight-bold"></i>
                            </button>
                            <input type="text" name="quantity"
                                   class="form-control input-number text-center cart-qty-field"
                                   placeholder="1" value="1" min="1" max="100">
                            <button class="btn btn-number text-dark p-2" type="button" data-type="plus"
                                    data-field="quantity">
                                    <i class="tio-add font-weight-bold"></i>
                            </button>
                        </div>
                    </div>
                </div>
                @php($addOns = json_decode($product->add_ons))
                @if(count($addOns) > 0)
                    <h3 class="pt-2">{{ translate('addon') }}</h3>

                    <div class="d-flex flex-wrap addon-wrap">
                        @foreach (\App\Model\AddOn::whereIn('id', $addOns)->get() as $key => $add_on)
                            <div class="addon-item flex-column">
                                <input type="hidden" name="addon-price{{ $add_on->id }}" value="{{$add_on->price}}">
                                <input class="btn-check addon-chek" type="checkbox"
                                       id="addon{{ $key }}" onchange="addon_quantity_input_toggle(event)"
                                       name="addon_id[]" value="{{ $add_on->id }}"
                                       autocomplete="off">
                                <label class="d-flex align-items-center btn btn-sm check-label addon-input mb-0 h-100 break-all"
                                       for="addon{{ $key }}">{{ $add_on->name }} <br>
                                    {{ \App\CentralLogics\Helpers::set_symbol($add_on->price) }}
                                </label>
                                <label class="input-group addon-quantity-input shadow bg-white rounded mb-0 d-flex align-items-center"
                                       for="addon{{ $key }}">
                                    <button class="btn btn-sm h-100 text-dark px-0" type="button"
                                            onclick="this.parentNode.querySelector('input[type=number]').stepDown(), getVariantPrice()">
                                        <i class="tio-remove  font-weight-bold"></i></button>
                                    <input type="number" name="addon-quantity{{ $add_on->id }}"
                                           class="text-center border-0 h-100"
                                           placeholder="1" value="1" min="1" max="100" readonly>
                                    <button class="btn btn-sm h-100 text-dark px-0" type="button"
                                            onclick="this.parentNode.querySelector('input[type=number]').stepUp(), getVariantPrice()">
                                        <i class="tio-add  font-weight-bold"></i></button>
                                </label>
                            </div>
                        @endforeach
                    </div>
                @endif
                <div class="row no-gutters mt-4 text-dark" id="chosen_price_div">
                    <div class="col-2">
                        <div class="product-description-label">{{translate('Total_Price')}}:</div>
                    </div>
                    <div class="col-10">
                        <div class="product-price">
                            <strong id="chosen_price"></strong>
                        </div>
                    </div>
                </div>

                <div class="d-flex justify-content-center align-items-center gap-2 mt-2">
                    <button class="btn btn-primary px-md-5 add-to-cart-button" type="button">
                        <i class="tio-shopping-cart"></i>
                        {{translate('add')}}
                    </button>
                    @if ($product->has_free)
                        <button class="btn btn-secondary px-md-5" id="show-free-product" type="button">
                        <i class="tio-gift"></i>
                        {{translate('add free product')}}
                    </button>
                    @endif
                </div>

            </form>
        </div>
    </div>
</div>

<script>
    "use strict";

    cartQuantityInitialize();
    getVariantPrice();

    $('#add-to-cart-form input').on('change', function () {
        getVariantPrice();
    });

    $('.show-more span').on('click', function(){
        $('.__descripiton-txt').toggleClass('__not-first-hidden')
        if($(this).hasClass('active')) {
            $('.show-more span').text('{{translate('See More')}}')
            $(this).removeClass('active')
        }else {
            $('.show-more span').text('{{translate('See Less')}}')
            $(this).addClass('active')
        }
    })

    $('.addon-chek').change(function() {
        addon_quantity_input_toggle($(this));
    });

    $('.decrease-quantity').click(function() {
        var input = $(this).closest('.addon-quantity-input').find('.addon-quantity');
        input.val(parseInt(input.val()) - 1);
        getVariantPrice();
    });

    $('.increase-quantity').click(function() {
        var input = $(this).closest('.addon-quantity-input').find('.addon-quantity');
        input.val(parseInt(input.val()) + 1);
        getVariantPrice();
    });

    $('.add-to-cart-button').click(function() {
        addToCart();
    });
    $('#show-free-product').click(function() {
        showFreeProduct();
    });
    
    function showFreeProduct(){
        var product_id = $('input[name="id"]').val();
        var category_id = $('input[name="category_id"]').val();
        var cat = JSON.parse(category_id);

         $.ajax({
            url: '{{ route('can_free', ':product_id') }}'.replace(':product_id', product_id),
            type: 'GET',
            data: {
                category_id: cat[0]?.id
            },
            success: function (response) {
                 console.log(response);

                 if (response.products) {
                     let modalBody = $('#free-product-modal .modal-body .row');
                     modalBody.empty(); // Clear any existing content in the modal body

                     // Loop through the products and generate HTML
                     response.products.forEach(product => {
                        product.price = 0;
                         const productHTML = `
                <div class="col-md-4 mb-3">
                    <div class="card">
                        <img src="../storage/app/public/product/${product.image}" class="card-img-top" alt="${product.name}">
                        <div class="card-body">
                            <h5 class="card-title">${product.name}</h5>
                            <p class="card-text">${product.description || 'No description available.'}</p>
                            <button class="btn btn-primary btn-sm" id="select-free-product" data-id="${product.id}">
                                Select
                            </button>
                        </div>
                    </div>
                </div>
            `;

                         modalBody.append(productHTML); // Add product HTML to modal body
                     });

                     // Show the modal
                     $('#free-product-modal').modal('show');
                 } else {
                     alert(response.message || 'No free products available.');
                 }
             },error: function (xhr, status, error) {
                console.error(error);
                // Handle errors here
            }
        });
    }
    $('#dismiss').click(function(){
        $('#free-product-modal').modal('hide');
    })
    $(document).on('click', '#select-free-product', function () {
        var id = $(this).data('id');
        console.log(id);
        $.ajax({
            url: 'pos/add-to-cart',
            type: 'POST',
            data: {
                id: id,
                is_free : true,
                quantity : 1,
                _token: '{{ csrf_token() }}'
            },
            success: function (response) {
                alert('Free product added to cart successfully.');
            },
            error: function (xhr, status, error) {
                console.error(error);
                alert('An error occurred while adding the free product to the cart.');
            }

        });
        $('#free-product-modal').modal('hide');
    });
</script>

